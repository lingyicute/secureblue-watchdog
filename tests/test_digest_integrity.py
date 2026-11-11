"""Digest verification must fail closed on non-sha256 or malformed digests."""
import hashlib
import io
import json
import os
import tempfile
import types
import unittest

from test_sbwatch import S


class TestDigestIntegrity(unittest.TestCase):
    HEX_A = "a" * 64
    HEX_B = "b" * 64

    def test_optional_tag_and_empty_header_are_accepted(self):
        S.check_digest(self.HEX_A, "latest", "manifest latest")
        S.check_digest(self.HEX_A, "", "manifest latest")
        S.check_digest(self.HEX_A, None, "manifest latest")

    def test_valid_sha256_digest_matches_case_insensitively(self):
        S.check_digest(self.HEX_A, "sha256:" + self.HEX_A, "blob")
        S.check_digest(self.HEX_A, "SHA256:" + self.HEX_A.upper(), "blob", required=True)

    def test_uppercase_or_malformed_or_other_algo_digests_fail_closed(self):
        bad = (
            "SHA256:" + self.HEX_B,
            "sha256:",
            "sha256:   ",
            "sha256:1234",
            "sha256:" + "g" * 64,
            "sha512:" + "a" * 128,
            "blake3:" + self.HEX_A,
        )
        for d in bad:
            with self.subTest(digest=d):
                with self.assertRaises(SystemExit):
                    S.check_digest(self.HEX_A, d, "manifest")

    def test_required_digest_rejects_empty_or_tag_like_values(self):
        for d in ("", None, "latest", "20260917"):
            with self.subTest(digest=d):
                with self.assertRaises(SystemExit):
                    S.check_digest(self.HEX_A, d, "layer", required=True)

    def test_resolve_rejects_malformed_descriptor_digests_and_canonicalizes_case(self):
        plat = json.dumps({"layers": [], "config": {"digest": "sha256:bad"}}).encode()
        plat_hex = hashlib.sha256(plat).hexdigest()
        idx = json.dumps({"manifests": [{
            "digest": "SHA256:" + plat_hex.upper(),
            "platform": {"architecture": "amd64", "os": "linux"}}]}).encode()
        idx_hex = hashlib.sha256(idx).hexdigest()

        class Resp(io.BytesIO):
            headers = {"Docker-Content-Digest": "SHA256:" + idx_hex.upper()}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        reg = S.Registry("secureblue/x", arch="amd64")
        reg._open = lambda path, accept: Resp(idx)
        reg.get = lambda path, accept: plat if path.startswith("manifests/") else b"{}"
        out = reg.resolve("latest", light=True)
        self.assertEqual(out["index_digest"], "sha256:" + idx_hex)
        self.assertEqual(out["digest"], "sha256:" + plat_hex)
        with self.assertRaises(SystemExit):
            reg.resolve("latest", light=False)

    def test_fetch_blob_removes_dest_on_digest_failure(self):
        class Resp(io.BytesIO):
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        reg = types.SimpleNamespace(_open=lambda path, accept: Resp(b"tampered payload"))
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "layer.tar")
            with self.assertRaises(SystemExit):
                S.Registry.fetch_blob(reg, "sha256:" + self.HEX_A, dest)
            self.assertFalse(os.path.exists(dest))


if __name__ == "__main__":
    unittest.main()
