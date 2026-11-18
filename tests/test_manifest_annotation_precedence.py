"""Manifest annotations take precedence over stale intermediate config Labels."""
import json
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestResolveManifestAnnotationsPrecedence(unittest.TestCase):
    def test_manifest_annotations_are_not_clobbered_by_stale_config_labels(self):
        cfg_bytes = json.dumps({
            "architecture": "amd64", "os": "linux",
            "created": "2026-11-16T03:44:35Z",
            "config": {
                "Labels": {
                    "org.opencontainers.image.created": "2026-11-16T03:04:11.261870326+00:00",
                    "org.blue-build.build-id": "build-123",
                }
            },
        }).encode("utf-8")
        cfg_dig = "sha256:" + S.hashlib.sha256(cfg_bytes).hexdigest()
        man_bytes = json.dumps({
            "schemaVersion": 2,
            "config": {"digest": cfg_dig},
            "annotations": {
                "org.opencontainers.image.created": "2026-11-16T03:44:35.27268298Z",
                "org.opencontainers.image.version": "45.20261116.0",
            },
            "layers": [],
        }).encode("utf-8")
        man_dig = "sha256:" + S.hashlib.sha256(man_bytes).hexdigest()

        class FakeResp:
            def __init__(self, body, headers):
                self._body = body
                self.headers = headers

            def read(self, n=-1):
                if not self._body:
                    return b""
                out, self._body = self._body, b""
                return out

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        reg = S.Registry("secureblue/silverblue-main-hardened")
        with patch.object(reg, "_open", return_value=FakeResp(
            man_bytes,
            {"Docker-Content-Digest": man_dig,
             "Content-Type": "application/vnd.oci.image.manifest.v1+json"},
        )), patch.object(reg, "get", return_value=cfg_bytes):
            resolved = reg.resolve("20261116", light=False)

        self.assertEqual(
            resolved["annotations"]["org.opencontainers.image.created"],
            "2026-11-16T03:44:35.27268298Z",
        )
        self.assertEqual(resolved["annotations"]["org.blue-build.build-id"], "build-123")
        self.assertEqual(resolved["created"], "2026-11-16T03:44:35Z")
        self.assertEqual(resolved["created_order"], "2026-11-16T03:44:35.272682980Z")
        same_second = dict(resolved, created_order="2026-11-16T03:44:35.100000000Z")
        self.assertTrue(S.orient(resolved, same_second)[2])

    def test_resolving_the_platform_through_an_index_keeps_platform_metadata(self):
        version = "org.opencontainers.image.version"
        cfg = json.dumps({"architecture": "amd64", "os": "linux", "config": {
            "Labels": {version: "45.20261117.0"}}}).encode()
        digest = lambda data: "sha256:" + S.hashlib.sha256(data).hexdigest()
        platform = json.dumps({"schemaVersion": 2, "config": {"digest": digest(cfg)},
                               "layers": []}).encode()
        index = json.dumps({"schemaVersion": 2, "annotations": {version: "other-index-version"},
                            "manifests": [{"digest": digest(platform),
                                           "platform": {"os": "linux", "architecture": "amd64"},
                                           "annotations": {version: "other-descriptor-version"}}]}).encode()
        from io import BytesIO
        reg = S.Registry("secureblue/silverblue-main-hardened")
        for ref, raw in (("latest", index), (digest(platform), platform)):
            with self.subTest(ref=ref):
                response = BytesIO(raw)
                response.headers = {}
                with patch.object(reg, "_open", return_value=response), patch.object(
                    reg, "get", side_effect=lambda path, _: platform if path.startswith("manifests/") else cfg,
                ):
                    result = reg.resolve(ref)
                self.assertEqual(result["digest"], digest(platform))
                self.assertEqual(result["annotations"][version], "45.20261117.0")


if __name__ == "__main__":
    unittest.main()
