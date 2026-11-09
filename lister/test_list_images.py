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


class Kustomize(unittest.TestCase):
    D2 = "sha256:" + "b" * 64

    def tree(self, files):
        import tempfile
        d = tempfile.mkdtemp()
        for path, text in files.items():
            os.makedirs(os.path.join(d, os.path.dirname(path)), exist_ok=True)
            with open(os.path.join(d, path), "w") as fh:
                fh.write(text)
        return d, sorted(files)

    def listed(self, files, paths=("system/*",)):
        repo, tracked = self.tree(files)
        cfg = {"platform": "linux/arm64", "default_host": "h"}
        return [(e["ref"], e["source"]) for e in li.list_yaml(repo, tracked, cfg, {"paths": list(paths)})]

    COMPONENTS = "spec:\n  containers:\n  - image: ghcr.io/example/controller:v1.7.1\n  - image: ghcr.io/example/other:v2\n"

    def test_new_name_tag_and_digest(self):
        got = self.listed({
            "system/components.yaml": self.COMPONENTS,
            "system/kustomization.yaml": "resources: [components.yaml]\nimages:\n"
                f"- name: ghcr.io/example/controller\n  newName: registry.example/hardened-controller\n"
                f"  newTag: \"1.7.1\"\n  digest: {D}\n"})
        self.assertIn((f"registry.example/hardened-controller:1.7.1@{D}", "system/components.yaml:3"), got)
        self.assertIn(("ghcr.io/example/other:v2", "system/components.yaml:4"), got)

    def test_digest_alone_drops_the_tag_and_newtag_alone_the_digest(self):
        self.assertEqual(li.apply_images("a.example/x:1", [[{"name": "a.example/x", "digest": D}]]), f"a.example/x@{D}")
        self.assertEqual(li.apply_images(f"a.example/x:1@{D}", [[{"name": "a.example/x", "newTag": 2}]]), "a.example/x:2")

    def test_a_file_the_kustomization_does_not_build_is_untouched(self):
        got = self.listed({
            "system/components.yaml": self.COMPONENTS,
            "system/kustomization.yaml": "resources: [other.yaml]\nimages:\n- name: ghcr.io/example/controller\n  newTag: v9\n",
            "system/other.yaml": "image: busybox:1\n"})
        self.assertIn(("ghcr.io/example/controller:v1.7.1", "system/components.yaml:3"), got)

    def test_a_directory_resource_covers_the_files_under_it_and_inner_goes_first(self):
        got = self.listed({
            "system/apps/deploy.yaml": "image: ghcr.io/example/controller:v1\n",
            "system/apps/kustomization.yaml": "resources: [deploy.yaml]\nimages:\n"
                "- name: ghcr.io/example/controller\n  newName: registry.example/inner\n",
            "system/kustomization.yaml": "resources: [apps, https://example.com/remote.yaml]\nimages:\n"
                f"- name: registry.example/inner\n  digest: {self.D2}\n"}, paths=("system/**", "system/*"))
        self.assertIn((f"registry.example/inner@{self.D2}", "system/apps/deploy.yaml:1"), got)


if __name__ == "__main__":
    unittest.main()
