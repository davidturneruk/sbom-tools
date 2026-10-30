#!/usr/bin/env python3
"""Tests for sbom-diff.py. Run: python3 diff/test_sbom_diff.py"""
import importlib.util
import json
import os
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "sbom_diff", os.path.join(os.path.dirname(__file__), "sbom-diff.py"))
sd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sd)


def e(repo, digest, source="a.yml:1", host="h", tag="1"):
    return {"repository": repo, "digest": "sha256:" + digest * 64, "tag": tag, "host": host,
            "platform": "linux/amd64", "source": source, "ref": f"{repo}:{tag}"}


class Collect(unittest.TestCase):
    def test_same_image_in_many_scripts_is_scanned_once(self):
        got = sd.collect([e("docker.io/library/alpine", "a", "x.sh:1"),
                          e("docker.io/library/alpine", "a", "y.sh:9")])
        (only,) = got.values()
        self.assertEqual(only["sha256:" + "a" * 64]["sources"], ["x.sh:1", "y.sh:9"])

    def test_local_images_are_skipped(self):
        self.assertEqual(sd.collect([{**e("local/x", "a"), "digest": None}]), {})

    def test_hosts_are_kept_apart(self):
        # The same image on two hosts is two things to compare.
        got = sd.collect([e("quay.io/n", "a", host="one"), e("quay.io/n", "a", host="two")])
        self.assertEqual(len(got), 2)


class Packages(unittest.TestCase):
    def test_nested_components_and_qualifiers(self):
        doc = {"components": [
            {"purl": "pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64", "components": [
                {"purl": "pkg:golang/github.com/A/b@v1.0.0"}]},
            {"purl": "pkg:apk/alpine/musl@1.2.6-r3"},  # two versions of one package
            {"type": "file", "name": "/etc/passwd"},   # no purl: ignored
        ]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
        try:
            got = sd.packages(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(got, {("apk", "alpine/musl"): {"1.2.6-r2", "1.2.6-r3"},
                               ("golang", "github.com/a/b"): {"v1.0.0"}})

    def test_diff(self):
        old = {("apk", "a"): {"1"}, ("apk", "b"): {"1"}}
        new = {("apk", "a"): {"2"}, ("apk", "c"): {"1"}}
        added, removed, changed = sd.diff_packages(old, new)
        self.assertEqual(added, [("apk", "c")])
        self.assertEqual(removed, [("apk", "b")])
        self.assertEqual(changed, [(("apk", "a"), {"1"}, {"2"})])


class Vulns(unittest.TestCase):
    MATCHES = {"matches": [
        {"vulnerability": {"id": "CVE-2026-5450", "severity": "High",
                           "fix": {"state": "fixed", "versions": ["2.41-12+deb13u4"]}},
         "artifact": {"name": "libc6", "version": "2.41-12+deb13u3", "upstreams": [{"name": "glibc"}]}},
        {"vulnerability": {"id": "CVE-2026-1", "severity": "Low", "fix": {"state": "not-fixed"}},
         "artifact": {"name": "grub-efi-amd64-signed", "version": "1.215+2.14-2ubuntu1",
                      "upstreams": [{"name": "grub2-signed", "version": "1.215"}]}},
        {"vulnerability": {"id": "GHSA-x", "severity": "Medium", "fix": {}},
         "artifact": {"name": "requests", "version": "2.0.0"}},
    ]}

    def test_source_package_is_kept(self):
        run = sd.run
        sd.run = lambda *a, **k: json.dumps(self.MATCHES).encode()
        try:
            with tempfile.NamedTemporaryFile() as fh:
                got = sd.vulns(fh.name, "grype")
        finally:
            sd.run = run
        self.assertEqual(got[("CVE-2026-5450", "libc6")]["upstream"], "glibc")
        self.assertEqual(got[("CVE-2026-5450", "libc6")]["upstream_version"], "")
        self.assertEqual(got[("CVE-2026-5450", "libc6")]["fixed_in"], "2.41-12+deb13u4")
        self.assertEqual(got[("CVE-2026-1", "grub-efi-amd64-signed")]["upstream_version"], "1.215")
        self.assertEqual(got[("GHSA-x", "requests")]["upstream"], "")


class PullRef(unittest.TestCase):
    def test_docker_hub_tries_the_mirror_first(self):
        got = sd.pull_ref(e("docker.io/library/alpine", "a"), "mirror.gcr.io")
        self.assertEqual([r.split("@")[0] for r in got], ["mirror.gcr.io/library/alpine", "docker.io/library/alpine"])

    def test_other_registries_never_use_it(self):
        self.assertEqual(len(sd.pull_ref(e("ghcr.io/x/y", "a"), "mirror.gcr.io")), 1)


if __name__ == "__main__":
    unittest.main()
