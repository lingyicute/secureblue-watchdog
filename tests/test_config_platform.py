"""A signed per-platform digest is not a promise about the requested --arch."""
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestConfigPlatform(unittest.TestCase):
    def resolve(self, requested, os_name="linux", arch="amd64"):
        cfg = json.dumps({"architecture": arch, "os": os_name}).encode()
        man = json.dumps({"config": {"digest": "sha256:" + hashlib.sha256(cfg).hexdigest()},
                          "layers": []}).encode()
        ref = "sha256:" + hashlib.sha256(man).hexdigest()
        reg = S.Registry("secureblue/silverblue-main-hardened", arch=requested)
        response = io.BytesIO(man)
        response.headers = {}
        with patch.object(reg, "_open", return_value=response), \
                patch.object(reg, "get", return_value=cfg):
            return reg.resolve(ref)

    def test_direct_digest_cannot_switch_architectures(self):
        with self.assertRaises(S.NoArchManifest):
            self.resolve("arm64")

    def test_foreign_os_is_not_a_linux_image(self):
        with self.assertRaises(S.NoArchManifest):
            self.resolve("amd64", os_name="windows")

    def test_absent_platform_is_not_a_match(self):
        with self.assertRaises(S.MalformedManifest):
            self.resolve("amd64", arch=None)

    def test_requested_platform_still_resolves(self):
        self.assertEqual(self.resolve("amd64")["config"]["architecture"], "amd64")
