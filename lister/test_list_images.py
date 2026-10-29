#!/usr/bin/env python3
"""Tests for list-images.py. Run: python3 lister/test_list_images.py"""
import importlib.util
import os
import unittest

spec = importlib.util.spec_from_file_location(
    "list_images", os.path.join(os.path.dirname(__file__), "list-images.py"))
li = importlib.util.module_from_spec(spec)
spec.loader.exec_module(li)

D = "sha256:" + "a" * 64


class ParseRef(unittest.TestCase):
    def test_docker_hub_short_names(self):
        # Docker's own normalisation: a bare name is library/, a one-part path is docker.io/.
        self.assertEqual(li.parse_ref("alpine:3.24.2")["repository"], "docker.io/library/alpine")
        self.assertEqual(li.parse_ref("example/app:1.2.3")["repository"], "docker.io/example/app")
        self.assertEqual(li.parse_ref("docker.io/nginx:1.29.0")["repository"], "docker.io/library/nginx")
        self.assertEqual(li.parse_ref("index.docker.io/example/tool:1.0")["repository"], "docker.io/example/tool")

    def test_registries_and_ports(self):
        self.assertEqual(li.parse_ref("ghcr.io/a/b:1")["repository"], "ghcr.io/a/b")
        self.assertEqual(li.parse_ref("localhost:5000/x:1")["repository"], "localhost:5000/x")
        self.assertEqual(li.parse_ref("registry.k8s.io/example/nested/app:v1.0.0")["repository"],
                         "registry.k8s.io/example/nested/app")

    def test_numeric_tags_are_not_ports(self):
        self.assertEqual(li.parse_ref("node:24")["repository"], "docker.io/library/node")
        self.assertEqual(li.parse_ref("node:24")["tag"], "24")
        self.assertEqual(li.parse_ref("ghcr.io/a/b:1")["tag"], "1")
        r = li.parse_ref("registry.example:5000/a/b:7")
        self.assertEqual((r["repository"], r["tag"]), ("registry.example:5000/a/b", "7"))

    def test_tag_and_digest(self):
        r = li.parse_ref(f"ghcr.io/example/app:2026.1.0@{D}")
        self.assertEqual((r["tag"], r["digest"]), ("2026.1.0", D))
        r = li.parse_ref(f"example/app@{D}")
        self.assertEqual((r["repository"], r["tag"], r["digest"]), ("docker.io/example/app", None, D))

    def test_local_images_keep_their_name(self):
        self.assertEqual(li.parse_ref("local/example:0.1.0")["repository"], "local/example")

    def test_rejects_garbage(self):
        self.assertIsNone(li.parse_ref("${IMAGE}"))
        self.assertIsNone(li.parse_ref("Upper/Case:1"))


class YamlImages(unittest.TestCase):
    def test_image_keys_with_lines(self):
        text = "services:\n  a:\n    image: alpine:3.24.2\n  b:\n    build: .\n"
        self.assertEqual(list(li.yaml_images(text)), [("alpine:3.24.2", 3)])

    def test_image_mappings_are_not_refs(self):
        # Helm values and CRD schemas use image: as a mapping, which is not a reference.
        text = "image:\n  repository: x\n  tag: y\n"
        self.assertEqual(list(li.yaml_images(text)), [])

    def test_images_passed_as_flags(self):
        # cert-manager passes its ACME solver image as an argument.
        text = ("spec:\n  containers:\n  - image: quay.io/example/controller:v1.0.0\n"
                "    args:\n    - --v=2\n    - --acme-http01-solver-image=quay.io/example/solver:v1.0.0\n")
        self.assertEqual([r for r, _ in li.yaml_images(text)],
                         ["quay.io/example/controller:v1.0.0",
                          "quay.io/example/solver:v1.0.0"])

    def test_multiple_documents(self):
        text = "image: a:1\n---\n---\nimage: b:2\n"
        self.assertEqual(list(li.yaml_images(text)), [("a:1", 1), ("b:2", 4)])


class ValuesContent(unittest.TestCase):
    """K3s deploys some charts itself; a HelmChartConfig overrides their values,
    image included, inside a string."""

    def doc(self, values):
        return ("apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: app\n"
                "spec:\n  valuesContent: |-\n" + "".join(f"    {l}\n" for l in values))

    def test_registry_repository_and_tag(self):
        text = self.doc(["resources: {}", "image:", "  registry: registry.example", "  repository: app",
                         "  tag: \"1.2.3\""])
        self.assertEqual(list(li.yaml_images(text)), [("registry.example/app:1.2.3", 8)])

    def test_registry_in_repository_and_digest_in_tag(self):
        # Some bundled charts ignore image.registry, so the registry goes in repository.
        text = self.doc(["image:", "  repository: registry.example/app", f"  tag: \"1.2.3@{D}\""])
        [(ref, _)] = li.yaml_images(text)
        self.assertEqual(ref, f"registry.example/app:1.2.3@{D}")
        self.assertEqual(li.parse_ref(ref)["digest"], D)

    def test_no_image_or_no_repository(self):
        self.assertEqual(list(li.yaml_images(self.doc(["resources: {}"]))), [])
        self.assertEqual(list(li.yaml_images(self.doc(["image:", "  tag: \"1.0\""]))), [])
        self.assertEqual(list(li.yaml_images(self.doc(["not: [valid"]))), [])


if __name__ == "__main__":
    unittest.main()
