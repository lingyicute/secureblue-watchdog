"""Uppercase or padded saved digests keep rollback direction and no-update checks."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestStateDigestNormalization(unittest.TestCase):
    def test_uppercase_state_digest_preserves_rollback_direction(self):
        old_dig = "sha256:" + "a" * 64
        new_dig = "sha256:" + "b" * 64
        img_old = {"ref": "latest", "digest": old_dig, "index_digest": old_dig,
                   "created": "2026-11-20T00:00:00Z", "created_order": "2026-11-20T00:00:00.000000000Z",
                   "annotations": {"org.opencontainers.image.version": "45.20261120.0"}, "layers": []}
        img_new = {"ref": new_dig, "digest": new_dig, "index_digest": new_dig,
                   "created": "2026-11-21T00:00:00Z", "created_order": "2026-11-21T00:00:00.000000000Z",
                   "annotations": {"org.opencontainers.image.version": "45.20261121.0"}, "layers": []}
        pa = S.PackageTable({"curl": pkg("curl", "8.21.0-1.fc45")})
        pb = S.PackageTable({"curl": pkg("curl", "8.20.0-1.fc45")})

        def fake_resolve(reg, ref, light=False):
            return dict(img_old if ref == "latest" else img_new)

        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")
            report_path = os.path.join(tmp, "report.md")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump({"image": "ghcr.io/secureblue/x", "arch": "amd64", "tag": "latest",
                           "digest": new_dig.upper(), "created": img_new["created"],
                           "analysis_incomplete": False}, fh)
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=fake_resolve), \
                    patch.object(S, "load_pkglist", side_effect=[pa, pb]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "secureblue/x", "--state", state_path,
                             "--report", report_path, "--scan", "0", "--no-bodhi",
                             "--no-audit", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            with open(report_path + ".json", encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["from_digest"], new_dig)
            self.assertEqual(doc["digest"], old_dig)
            self.assertEqual(doc["changed"][0]["dir"], "downgrade")


if __name__ == "__main__":
    unittest.main()
