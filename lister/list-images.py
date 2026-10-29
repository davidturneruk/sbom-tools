#!/usr/bin/env python3
"""List every container image a repository says should run.

Prints one JSON object per image reference to stdout:

  {"ref": "...", "repository": "ghcr.io/x/y", "tag": "1.2.3", "digest": "sha256:...",
   "host": "myhost", "platform": "linux/amd64", "kind": "compose", "source": "path:line"}

What to read, and which host each file belongs to, comes from a config file in the
repository being listed (default sbom/lister.yaml), so this script holds no knowledge
of any particular estate. See README.md for the config format.

Sources:
  compose        image: in docker-compose.yml files
  scripts        image words such as alpine:3.24@sha256:... in tracked *.sh files
  yaml           image: in other YAML files (an MCP catalog, Kubernetes manifests), and
                 the image a K3s HelmChart or HelmChartConfig sets in its valuesContent
  helm           images in each Flux HelmRelease, rendered with `helm template`, so
                 chart defaults are listed too (needs network and helm)
  k3s            the k3s-images.txt that the pinned K3s release publishes (needs network)

--offline skips helm and k3s. --resolve fills in the digest of refs that have none,
with `crane digest` (needs network and crane).
"""
import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import yaml

# A reference: [registry/]path[:tag][@sha256:digest]
REF_RE = re.compile(
    # The first component may carry a registry port, but only when a path follows it:
    # otherwise node:24 would read as host "node", port 24.
    r"^(?P<name>[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+(?=/))?(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{0,127}))?"
    r"(?:@(?P<digest>sha256:[a-f0-9]{64}))?$"
)
# An image passed as a flag, e.g. cert-manager's --acme-http01-solver-image=...
ARG_IMAGE_RE = re.compile(r"^--[a-z0-9-]*image=(\S+)$")


def die(msg):
    print(f"list-images: {msg}", file=sys.stderr)
    sys.exit(2)


def parse_ref(ref):
    """Split a reference and normalise its repository the way Docker does."""
    m = REF_RE.match(ref)
    if not m:
        return None
    name, tag, digest = m.group("name"), m.group("tag"), m.group("digest")
    if name.startswith(("docker.io/", "index.docker.io/")):
        name = name.split("/", 1)[1]  # so docker.io/nginx becomes docker.io/library/nginx
    first = name.split("/")[0]
    if "/" not in name:
        repository = f"docker.io/library/{name}"
    elif "." in first or ":" in first or first == "localhost":
        repository = name
    elif first == "local":
        repository = name  # built on the box; there is no registry to look up
    else:
        repository = f"docker.io/{name}"
    return {"repository": repository, "tag": tag, "digest": digest}


def git_files(repo):
    out = subprocess.run(["git", "-C", repo, "ls-files", "-z"], capture_output=True, check=True)
    return [f for f in out.stdout.decode().split("\0") if f]


def matches(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns or [])


def host_for(path, cfg):
    for pattern, host in (cfg.get("hosts") or {}).items():
        if fnmatch.fnmatch(path, pattern):
            return host
    return cfg["default_host"]


def values_image(text, first_line):
    """The image a K3s HelmChart or HelmChartConfig's valuesContent sets, spelt the way
    most charts take it: image.repository, with optional image.registry and image.tag (a
    tag may carry @sha256:...). Yields (ref, line) at most once; first_line is the line
    the content starts on."""
    try:
        node = yaml.compose(text)
    except yaml.YAMLError:
        return
    if not isinstance(node, yaml.MappingNode):
        return
    for k, v in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == "image" and isinstance(v, yaml.MappingNode):
            parts = {kk.value: vv.value for kk, vv in v.value
                     if isinstance(kk, yaml.ScalarNode) and isinstance(vv, yaml.ScalarNode)}
            if not parts.get("repository"):
                return
            ref = f"{parts['registry']}/{parts['repository']}" if parts.get("registry") else parts["repository"]
            if parts.get("tag"):
                ref += f":{parts['tag']}"
            yield ref, first_line + k.start_mark.line
            return


def yaml_images(text):
    """Yield (value, line) for every scalar `image:` mapping value, every image passed
    in an args list as --something-image=REF, and the image a valuesContent string sets
    (values_image). Line numbers are 1-based."""
    try:
        docs = list(yaml.compose_all(text))
    except yaml.YAMLError as e:
        raise ValueError(f"not valid YAML: {e}")

    def walk(node):
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode) and k.value == "image" and isinstance(v, yaml.ScalarNode):
                    yield v.value, v.start_mark.line + 1
                elif isinstance(k, yaml.ScalarNode) and k.value == "valuesContent" and isinstance(v, yaml.ScalarNode):
                    # A block scalar's content starts the line after its indicator.
                    yield from values_image(v.value, v.start_mark.line + 2)
                elif isinstance(k, yaml.ScalarNode) and k.value in ("args", "command") and isinstance(v, yaml.SequenceNode):
                    for item in v.value:
                        if isinstance(item, yaml.ScalarNode):
                            m = ARG_IMAGE_RE.match(item.value)
                            if m:
                                yield m.group(1), item.start_mark.line + 1
                yield from walk(v)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                yield from walk(item)

    for doc in docs:
        if doc is not None:
            yield from walk(doc)


def entry(ref, kind, source, host, platform):
    parsed = parse_ref(ref)
    if parsed is None:
        die(f"{source}: cannot parse image reference {ref!r}")
    return {"ref": ref, **parsed, "host": host, "platform": platform, "kind": kind, "source": source}


def list_compose(repo, files, cfg, src):
    for f in files:
        if os.path.basename(f) != "docker-compose.yml" or matches(f, src.get("exclude")):
            continue
        with open(os.path.join(repo, f)) as fh:
            for ref, line in yaml_images(fh.read()):
                yield entry(ref, "compose", f"{f}:{line}", host_for(f, cfg), cfg["platform"])


def list_scripts(repo, files, cfg, src):
    words = "|".join(re.escape(w) for w in src["images"])
    # The image word, its tag and its digest; the pin check enforces that the digest is there.
    pat = re.compile(rf'(?:^|[\s"=])((?:{words}):[A-Za-z0-9._-]+(?:@sha256:[a-f0-9]{{64}})?)')
    for f in files:
        if not f.endswith(".sh") or matches(f, src.get("exclude")):
            continue
        with open(os.path.join(repo, f), errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if line.lstrip().startswith("#"):
                    continue
                for m in pat.finditer(line):
                    yield entry(m.group(1), "script", f"{f}:{n}", host_for(f, cfg), cfg["platform"])


def list_yaml(repo, files, cfg, src):
    for f in files:
        if not f.endswith((".yaml", ".yml")) or not matches(f, src["paths"]) or matches(f, src.get("exclude")):
            continue
        with open(os.path.join(repo, f)) as fh:
            text = fh.read()
        try:
            found = list(yaml_images(text))
        except ValueError as e:
            die(f"{f}: {e}")
        for ref, line in found:
            yield entry(ref, src.get("kind", "yaml"), f"{f}:{line}", host_for(f, cfg), cfg["platform"])


def k3s_version(repo, src):
    with open(os.path.join(repo, src["inventory"])) as fh:
        inv = yaml.safe_load(fh)
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == src.get("key", "k3s_version") and isinstance(v, str):
                    found.append(v)
                walk(v)
        elif isinstance(o, list):
            for i in o:
                walk(i)

    walk(inv)
    if len(set(found)) != 1:
        die(f"{src['inventory']}: expected one {src.get('key', 'k3s_version')}, found {sorted(set(found))}")
    return found[0]


def list_helm(repo, files, cfg, src, helm_cmd, kube_version):
    docs = []
    for f in files:
        if not matches(f, src["paths"]) or not f.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(repo, f)) as fh:
            for d in yaml.safe_load_all(fh):
                if isinstance(d, dict) and d.get("kind"):
                    docs.append((f, d))
    repos = {}
    for f, d in docs:
        if d["kind"] == "HelmRepository":
            if d.get("spec", {}).get("type") == "oci":
                die(f"{f}: OCI HelmRepository {d['metadata']['name']} is not supported yet")
            repos[d["metadata"]["name"]] = d["spec"]["url"]
    for f, d in docs:
        if d["kind"] != "HelmRelease":
            continue
        spec = d["spec"]
        chart = spec["chart"]["spec"]
        url = repos.get(chart["sourceRef"]["name"])
        if not url:
            die(f"{f}: HelmRelease {d['metadata']['name']} uses unknown source {chart['sourceRef']['name']}")
        if spec.get("valuesFrom"):
            die(f"{f}: HelmRelease {d['metadata']['name']} uses valuesFrom, which the lister can't read")
        name = spec.get("releaseName") or d["metadata"]["name"]
        ns = spec.get("targetNamespace") or d["metadata"].get("namespace", "default")
        cmd = shlex.split(helm_cmd) + [
            "template", name, chart["chart"], "--repo", url, "--version", str(chart["version"]),
            "--namespace", ns, "--kube-version", kube_version, "-f", "-",
        ]
        values = yaml.safe_dump(spec.get("values") or {}).encode()
        # One retry: chart repositories are static sites, and a 502 from one of them
        # would otherwise fail every check that lists this repo.
        for attempt in range(2):
            res = subprocess.run(cmd, input=values, capture_output=True)
            if res.returncode == 0:
                break
            if attempt == 0:
                time.sleep(5)
        if res.returncode != 0:
            die(f"{f}: helm template {name} failed: {res.stderr.decode().strip()}")
        seen = set()
        for ref, _ in yaml_images(res.stdout.decode()):
            if ref not in seen:
                seen.add(ref)
                src_desc = f"{f} (chart {chart['chart']} {chart['version']})"
                yield entry(ref, "helm", src_desc, host_for(f, cfg), cfg["platform"])


def list_k3s(cfg, version, src):
    url = ("https://github.com/k3s-io/k3s/releases/download/"
           f"{urllib.parse.quote(version, safe='')}/k3s-images.txt")
    with urllib.request.urlopen(url, timeout=30) as r:
        lines = r.read().decode().split()
    for ref in lines:
        yield entry(ref, "k3s", f"k3s {version} k3s-images.txt", src.get("host", cfg["default_host"]), cfg["platform"])


def resolve(entries, crane_cmd):
    """Fill in the index digest of each ref that has none. local/* refs are left alone."""
    cache = {}
    for e in entries:
        if e["digest"] or e["repository"].startswith("local/"):
            continue
        name = f"{e['repository']}:{e['tag'] or 'latest'}"
        if name not in cache:
            res = subprocess.run(shlex.split(crane_cmd) + ["digest", name], capture_output=True)
            if res.returncode != 0:
                die(f"crane digest {name} failed: {res.stderr.decode().strip()}")
            cache[name] = res.stdout.decode().strip()
        e["digest"] = cache[name]
        e["resolved"] = True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="repository to list (default: .)")
    ap.add_argument("--config", help="config file (default: <repo>/sbom/lister.yaml)")
    ap.add_argument("--offline", action="store_true", help="skip sources that need the network")
    ap.add_argument("--resolve", action="store_true", help="fill in missing digests with crane")
    ap.add_argument("--helm", default=os.environ.get("HELM", "helm"), help="helm command (env HELM)")
    ap.add_argument("--crane", default=os.environ.get("CRANE", "crane"), help="crane command (env CRANE)")
    args = ap.parse_args()

    cfg_path = args.config or os.path.join(args.repo, "sbom", "lister.yaml")
    with open(cfg_path) as fh:
        cfg = yaml.safe_load(fh)
    for key in ("platform", "default_host", "sources"):
        if key not in cfg:
            die(f"{cfg_path}: missing {key}")

    files = git_files(args.repo)
    out = []
    kube_version = None
    for src in cfg["sources"]:
        t = src["type"]
        if t == "compose":
            out += list_compose(args.repo, files, cfg, src)
        elif t == "scripts":
            out += list_scripts(args.repo, files, cfg, src)
        elif t == "yaml":
            out += list_yaml(args.repo, files, cfg, src)
        elif t == "k3s":
            version = k3s_version(args.repo, src)
            kube_version = version.lstrip("v").split("+")[0]
            if not args.offline:
                out += list_k3s(cfg, version, src)
        elif t == "helm":
            if not args.offline:
                if not kube_version:
                    die("a helm source needs a k3s source listed before it, for --kube-version")
                out += list_helm(args.repo, files, cfg, src, args.helm, kube_version)
        else:
            die(f"{cfg_path}: unknown source type {t!r}")

    if not out:
        # An empty list is never right: it means a source broke, and a broken lister
        # must not read as "nothing to check". (BusyBox grep did exactly that once.)
        die("found no images at all")
    if args.resolve:
        resolve(out, args.crane)
    for e in out:
        print(json.dumps(e, sort_keys=True))


if __name__ == "__main__":
    main()
