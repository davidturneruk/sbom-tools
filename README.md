# sbom-tools

Scripts for keeping a software bill of materials (SBOM) for a small self-hosted
estate: which container images it runs, what is inside them, and what a change
to them adds or removes.

This repo is public so that CI in other, private repos can pull it in at a
pinned commit. It holds scripts only. Everything specific to an estate (which
files to read, which host runs what) lives in a config file in the repo being
listed.

## lister/list-images.py

Lists every container image a repository says should run, one JSON object per
reference:

```json
{"ref": "alpine:3.24.2@sha256:…", "repository": "docker.io/library/alpine", "tag": "3.24.2",
 "digest": "sha256:…", "host": "myhost", "platform": "linux/amd64", "kind": "script",
 "source": "backup.sh:12"}
```

Repositories are normalised the way Docker does (`alpine` becomes
`docker.io/library/alpine`), so references written differently compare equal.
It fails if it finds no images at all: an empty list means a source broke, and
must not read as "nothing to check".

```sh
python3 lister/list-images.py --repo path/to/repo            # all sources
python3 lister/list-images.py --repo path/to/repo --offline  # no network: skips helm and k3s
python3 lister/list-images.py --repo path/to/repo --resolve  # fill in missing digests with crane
```

Needs Python 3 with PyYAML, and git. The `helm` source needs `helm`, and
`--resolve` needs `crane`; set `HELM` or `CRANE` to run them another way, for
example as containers:

```sh
export HELM="docker run --rm -i alpine/helm:4.0.1"
export CRANE="docker run --rm gcr.io/go-containerregistry/crane:v0.22.1"
```

### Config

Default location: `sbom/lister.yaml` in the repo being listed.

```yaml
platform: linux/amd64          # the platform every image here runs as
default_host: myhost           # the host for files no hosts: pattern matches
hosts:                         # optional: glob on the file path → host
  remote/*: remote-host
sources:
  - type: compose              # image: in every tracked docker-compose.yml
    exclude: [examples/upstream.yml]
  - type: scripts              # image words in tracked *.sh files
    images: [node, alpine, debian]
  - type: yaml                 # image: in matching YAML files
    kind: catalog              # optional label for the output's kind field
    paths: [catalogs/*.yaml]
  - type: k3s                  # the k3s-images.txt for the pinned K3s release
    inventory: inventory/hosts.yml
    key: k3s_version           # optional, the default
  - type: helm                 # each Flux HelmRelease, rendered with helm template
    paths: [clusters/*]
```

Patterns are shell globs on paths relative to the repo root, where `*` also
matches `/`.

What each source finds:

- **`yaml`** reads every scalar `image:` value, and any image passed as a
  `--…-image=` argument (cert-manager passes its ACME solver that way). An
  `image:` whose value is a mapping, as in Helm values or CRD schemas, isn't a
  reference and is skipped.
- **`helm`** renders each `HelmRelease` from its `HelmRepository`, with the
  release's inline `values`, and lists the images in the output, so chart
  defaults are included. Hooks are rendered too. `valuesFrom` and OCI chart
  repositories aren't supported, and say so instead of being skipped. A `k3s`
  source must come before it, because the K3s version sets `--kube-version`.
- **`yaml`** also lists the image a K3s `HelmChart` or `HelmChartConfig` sets in its
  `valuesContent` string (`image.repository`, optional `image.registry` and
  `image.tag`), which is how a bundled chart such as Traefik gets another image.
- **`k3s`** lists every image the K3s release publishes in `k3s-images.txt`,
  including ones a cluster may have disabled. Treat these as allowed, not as
  required.
- **`local/…`** images (built on the host, with no registry) are listed with no
  digest, and `--resolve` leaves them alone.

## diff/sbom-diff.py

Shows what a change does to the images a repository runs. It lists the images
at the base and head commits, and for each image whose digest changed (or that
was added) it generates an SBOM of the old and new digest with Syft, scans both
with Grype, and prints:

- packages added, removed and changed;
- vulnerabilities fixed and introduced, with a table of what was introduced.

```sh
python3 diff/sbom-diff.py --repo . --base main --head HEAD
```

The base defaults to `$CHAINGUARD_BASE_REVISION`, which Chainguard Checks sets
on a pull request.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Nothing that needs a human. |
| 1 | The change **introduces** a CRITICAL vulnerability that upstream has already fixed. That usually means upstream regressed. What a change leaves in place never fails it: a bump that fixes 12 CVEs and leaves 3 is still an improvement. |
| 3 | Tool error: Syft, Grype, helm or a registry failed even after one retry. It's reported as a tool error, so it can't be mistaken for a finding or for a clean result. |

Introduced HIGH and CRITICAL vulnerabilities also get a warning annotation on
the line that sets the image. Output uses Chainguard Checks' `::sandbox-summary::`
and `::warning file=…` lines, which read fine in a terminal too.

Settings:

| Flag | Env | Default | |
|---|---|---|---|
| `--syft` | `SYFT` | `syft` | Command for Syft |
| `--grype` | `GRYPE` | `grype` | Command for Grype |
| `--mirror` | `DOCKERHUB_MIRROR` | none | A Docker Hub mirror to try first, such as `mirror.gcr.io`. Shared CI egress IPs hit Docker Hub's per-IP anonymous limit. The digest is the same either way, and a miss falls back to Docker Hub. |
| `--workdir` | `SBOM_WORKDIR` | `/var/tmp` | Scratch space. Keep it on disk: large images don't fit a RAM-backed `/tmp`. |
| `--offline-lister` | | off | List without helm and k3s |

### Syft settings

Chosen in a bake-off against Trivy on three images (a large Python image, a
.NET image, and a single static Go binary):

- **Syft, not Trivy.** Syft found .NET runtime packs (`microsoft.netcore.app.runtime`) that Trivy
  missed. Most .NET CVEs land in the runtime. It also found Rust dependencies in
  shared libraries built with `cargo auditable`.
- **`--select-catalogers +sbom-cataloger`.** Python wheels ship SBOMs in
  `dist-info/sboms/` that list the native libraries they bundle. In one image,
  four wheels each carried their own OpenSSL, at versions older than the
  system's. Without this cataloger those copies don't appear in any SBOM.
- **No per-file entries** (`SYFT_FILE_METADATA_SELECTION=none`,
  `SYFT_FILE_EXECUTABLE_SELECTION=none`). That removed about 6,000 file
  components from a large image and lost no packages.

## Tests

```sh
python3 lister/test_list_images.py
```
