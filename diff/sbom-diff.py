#!/usr/bin/env python3
"""Show what a change does to the images a repository runs.

Lists the images at the base and head commits with lister/list-images.py, then for
each image whose digest changed (or that was added), generates an SBOM of the old and
new digest with Syft and scans both with Grype. Prints a Markdown summary of packages
added, removed and changed, and vulnerabilities fixed and introduced.

Exit codes:
  0  nothing that needs a human
  1  the change INTRODUCES a CRITICAL vulnerability that already has a fix upstream:
     upstream regressed, so a human should look before it merges. What a change leaves
     in place never fails it: a bump that fixes 12 CVEs and leaves 3 is still better.
  3  tool error: Syft, Grype, helm or a registry failed even after a retry. Reported as
     a tool error, so it is never mistaken for a finding, nor for a clean result.

Output follows Chainguard Checks' conventions (::sandbox-summary::, ::warning file=...),
which also read sensibly in a plain terminal.
"""
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LISTER = os.path.join(HERE, "..", "lister", "list-images.py")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

# Syft settings chosen in the bake-off (see README): read SBOMs that packages ship
# (Python wheels' dist-info/sboms/ list the libraries they bundle, such as their own
# OpenSSL), and leave out per-file entries, which nothing downstream uses.
SYFT_ENV = {
    "SYFT_FILE_METADATA_SELECTION": "none",
    "SYFT_FILE_EXECUTABLE_SELECTION": "none",
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
}
# No -q: it silences Syft's errors as well as its progress, which left a failed run with an
# empty error message. Progress goes to stderr, which is only shown when a run fails.
SYFT_ARGS = ["--select-catalogers", "+sbom-cataloger"]


class ToolError(Exception):
    pass


def run(cmd, env=None, input=None, retries=1):
    """Run a command, retrying once: registries and database downloads fail transiently."""
    for attempt in range(retries + 1):
        res = subprocess.run(cmd, capture_output=True, input=input,
                             env={**os.environ, **(env or {})})
        if res.returncode == 0:
            return res.stdout
        if attempt < retries:
            time.sleep(5)
    raise ToolError(f"{' '.join(cmd[:4])}… exited {res.returncode}: "
                    f"{res.stderr.decode(errors='replace').strip()[-500:]}")


def list_images(repo, rev, workdir, offline):
    """Lister output for one commit, checked out in a temporary worktree."""
    path = os.path.join(workdir, f"tree-{rev[:12]}")
    subprocess.run(["git", "-C", repo, "worktree", "add", "--detach", "-q", path, rev],
                   check=True, capture_output=True)
    try:
        cmd = [sys.executable, LISTER, "--repo", path, "--resolve"]
        cfg = os.path.join(repo, "sbom", "lister.yaml")  # the head's config reads both sides
        if os.path.exists(cfg):
            cmd += ["--config", cfg]
        if offline:
            cmd.append("--offline")
        out = run(cmd, retries=0)
        return [json.loads(line) for line in out.decode().splitlines() if line.strip()]
    finally:
        subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", path], capture_output=True)


def image_key(e):
    return (e["host"], e["repository"], e["platform"])


def collect(entries):
    """{(host, repository, platform): {digest: entry with all its sources}}"""
    out = {}
    for e in entries:
        if e["repository"].startswith("local/"):
            continue  # built on the host: no registry to scan
        d = out.setdefault(image_key(e), {})
        if e["digest"] in d:
            d[e["digest"]]["sources"].append(e["source"])
        else:
            d[e["digest"]] = {**e, "sources": [e["source"]]}
    return out


def pull_ref(e, mirror):
    """The reference Syft pulls. Docker Hub goes through the mirror first when one is set:
    shared CI egress IPs hit Docker Hub's per-IP anonymous limit. Same digest, same bytes."""
    repo = e["repository"]
    if mirror and repo.startswith("docker.io/"):
        return [f"{mirror}/{repo[len('docker.io/'):]}@{e['digest']}", f"{repo}@{e['digest']}"]
    return [f"{repo}@{e['digest']}"]


def sbom(e, syft, mirror, workdir):
    out = os.path.join(workdir, f"{e['digest'][7:19]}-{e['platform'].replace('/', '_')}.cdx.json")
    if os.path.exists(out):
        return out
    errors = []
    for ref in pull_ref(e, mirror):
        try:
            data = run(shlex.split(syft) + [f"registry:{ref}", "--platform", e["platform"],
                                            *SYFT_ARGS, "-o", "cyclonedx-json"], env=SYFT_ENV)
            with open(out, "wb") as fh:
                fh.write(data)
            return out
        except ToolError as err:
            errors.append(str(err))
    raise ToolError(" / ".join(errors))


def packages(path):
    """{(type, name): set(versions)} from a CycloneDX SBOM, nested components included."""
    with open(path) as fh:
        doc = json.load(fh)
    out = {}

    def walk(cs):
        for c in cs or []:
            purl = c.get("purl", "")
            if purl.startswith("pkg:") and "@" in purl:
                head, version = purl.split("?")[0].rsplit("@", 1)
                typ, _, name = head[4:].partition("/")
                out.setdefault((typ, name.lower()), set()).add(version)
            walk(c.get("components"))

    walk(doc.get("components"))
    return out


def vulns(path, grype):
    """{(vuln id, package name): match} from Grype, reading the SBOM's own file."""
    with open(path, "rb") as fh:
        data = run(shlex.split(grype) + ["-o", "json"], input=fh.read(),
                   env={"GRYPE_CHECK_FOR_APP_UPDATE": "false"})
    out = {}
    for m in json.loads(data).get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        fix = v.get("fix", {})
        key = (v["id"], a["name"])
        out[key] = {
            "id": v["id"], "package": a["name"], "version": a["version"],
            "severity": v.get("severity", "Unknown"),
            "fixed_in": ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else "",
        }
    return out


def sev_rank(s):
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)


def diff_packages(old, new):
    added = sorted(k for k in new if k not in old)
    removed = sorted(k for k in old if k not in new)
    changed = sorted((k, old[k], new[k]) for k in new if k in old and new[k] != old[k])
    return added, removed, changed


def fmt_versions(vs):
    return ", ".join(sorted(vs))


def report_image(name, old_e, new_e, pk, vu):
    added, removed, changed = pk
    introduced, fixed = vu
    lines = []
    old_desc = f"`{old_e['tag'] or ''}@{old_e['digest'][7:19]}`" if old_e else "*(new image)*"
    lines.append(f"### `{name}`: {old_desc} → `{new_e['tag'] or ''}@{new_e['digest'][7:19]}`")
    lines.append("")
    lines.append(f"Packages: **{len(added)}** added, **{len(removed)}** removed, **{len(changed)}** changed. "
                 f"Vulnerabilities: **{len(fixed)}** fixed, **{len(introduced)}** introduced.")
    lines.append("")
    if introduced:
        lines.append("| Introduced | Severity | Package | Fix |")
        lines.append("|---|---|---|---|")
        for v in sorted(introduced, key=lambda v: (sev_rank(v["severity"]), v["id"]))[:40]:
            lines.append(f"| {v['id']} | {v['severity']} | {v['package']} {v['version']} | {v['fixed_in'] or 'none yet'} |")
        lines.append("")
    if fixed:
        by_sev = {}
        for v in fixed:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        lines.append("Fixed: " + ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items(), key=lambda x: sev_rank(x[0]))) + ".")
        lines.append("")
    details = []
    if changed or added or removed:
        details.append("<details><summary>Package changes</summary>\n")
        for (typ, n), ov, nv in changed[:150]:
            details.append(f"- {typ} `{n}` {fmt_versions(ov)} → {fmt_versions(nv)}")
        for typ, n in added[:100]:
            details.append(f"- {typ} `{n}` added")
        for typ, n in removed[:100]:
            details.append(f"- {typ} `{n}` removed")
        details.append("\n</details>\n")
    return lines + details


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base", default=os.environ.get("CHAINGUARD_BASE_REVISION"),
                    help="base commit (default: $CHAINGUARD_BASE_REVISION)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--offline-lister", action="store_true", help="list without helm and k3s")
    ap.add_argument("--syft", default=os.environ.get("SYFT", "syft"))
    ap.add_argument("--grype", default=os.environ.get("GRYPE", "grype"))
    ap.add_argument("--mirror", default=os.environ.get("DOCKERHUB_MIRROR", ""),
                    help="Docker Hub mirror host to try first, e.g. mirror.gcr.io")
    ap.add_argument("--workdir", default=os.environ.get("SBOM_WORKDIR", "/var/tmp"),
                    help="scratch space on disk, not tmpfs (default /var/tmp)")
    args = ap.parse_args()
    if not args.base:
        print("::error::sbom-diff: no base commit (--base or CHAINGUARD_BASE_REVISION)")
        return 3

    workdir = tempfile.mkdtemp(prefix="sbom-diff-", dir=args.workdir)
    # Syft caches every layer under TMPDIR, /tmp by default. In CI /tmp can be RAM
    # (about 2 GB on a Chainguard Checks VM), which a large image fills: "no space
    # left on device". Every tool this runs gets the disk scratch space.
    os.environ["TMPDIR"] = workdir
    summary, annotations, gate = [], [], []
    try:
        base = collect(list_images(args.repo, args.base, workdir, args.offline_lister))
        head = collect(list_images(args.repo, args.head, workdir, args.offline_lister))

        changes = []  # (name, old entry or None, new entry)
        for key, digests in sorted(head.items()):
            old = base.get(key, {})
            for digest, e in digests.items():
                if digest in old:
                    continue
                # Pair with the old digest this replaced: the one no longer used, if exactly one.
                gone = [o for d, o in old.items() if d not in digests]
                changes.append((key[1] + (f" ({key[0]})" if key[0] else ""), gone[0] if len(gone) == 1 else None, e))
        removed_images = [k for k in base if k not in head]

        if not changes and not removed_images:
            summary.append("No image changed.")
        for name, old_e, new_e in changes:
            new_sbom = sbom(new_e, args.syft, args.mirror, workdir)
            new_pk, new_vu = packages(new_sbom), vulns(new_sbom, args.grype)
            if old_e:
                old_sbom = sbom(old_e, args.syft, args.mirror, workdir)
                old_pk, old_vu = packages(old_sbom), vulns(old_sbom, args.grype)
            else:
                old_pk, old_vu = {}, {}
            introduced = [v for k, v in new_vu.items() if k not in old_vu]
            fixed = [v for k, v in old_vu.items() if k not in new_vu]
            summary += report_image(name, old_e, new_e, diff_packages(old_pk, new_pk), (introduced, fixed))
            bad = [v for v in introduced if v["severity"] in ("Critical", "High")]
            if bad:
                worst = sorted(bad, key=lambda v: sev_rank(v["severity"]))
                path, _, line = new_e["sources"][0].partition(":")
                # One vulnerability can match several packages (libssl3 and libcrypto3, say).
                uniq = list(dict.fromkeys(v["id"] for v in worst))
                ids = ", ".join(uniq[:5]) + ("…" if len(uniq) > 5 else "")
                annotations.append(f"::warning file={path},line={line or 1}::{name} introduces "
                                   f"{len(bad)} HIGH/CRITICAL: {ids}")
            gate += [(name, v) for v in introduced if v["severity"] == "Critical" and v["fixed_in"]]
        for host, repository, platform in removed_images:
            summary.append(f"- `{repository}` ({host}) no longer used.")
    except ToolError as err:
        print("::sandbox-summary::")
        print("## SBOM diff: tool error\n")
        print("The diff could not be produced, so this result says nothing about the change. "
              "Rerun the check; if it fails again, the tool or a registry is broken.\n")
        print(f"```\n{err}\n```")
        print("::end-sandbox-summary::")
        print(f"::error::sbom-diff tool error: {str(err)[:300]}")
        return 3
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    title = ("## SBOM diff: introduces a fixable CRITICAL" if gate else "## SBOM diff")
    print("::sandbox-summary::")
    print(title + "\n")
    if gate:
        print("A CRITICAL vulnerability that upstream has already fixed appears in the new image. "
              "That usually means upstream regressed: look before merging.\n")
        for name, v in gate:
            print(f"- **{v['id']}** in {v['package']} {v['version']} ({name}); fixed in {v['fixed_in']}")
        print()
    print("\n".join(summary))
    print("::end-sandbox-summary::")
    for a in annotations[:50]:
        print(a)
    return 1 if gate else 0


if __name__ == "__main__":
    sys.exit(main())
