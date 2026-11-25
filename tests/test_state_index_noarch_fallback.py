"""NoArchManifest on a saved index digest falls back to the saved platform digest."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestStateIndexNoArchFallback(unittest.TestCase):
    def test_noarch_on_saved_index_falls_back_to_platform_digest(self):
        prev_idx = "sha256:" + "c" * 64
        prev_dig = "sha256:" + "a" * 64
        cur_dig = "sha256:" + "b" * 64
        img_prev = {"ref": prev_dig, "digest": prev_dig, "index_digest": prev_dig,
                    "created": "2026-11-20T00:00:00Z",
                    "annotations": {"org.opencontainers.image.version": "45.20261120.0"}, "layers": []}
        img_cur = {"ref": "latest", "digest": cur_dig, "index_digest": cur_dig,
                   "created": "2026-11-21T00:00:00Z",
                   "annotations": {"org.opencontainers.image.version": "45.20261121.0"}, "layers": []}
        seen = []

        def fake_resolve(reg, ref, light=False):
            seen.append(ref)
            if ref == prev_idx:
                raise S.NoArchManifest("no amd64")
            return dict(img_cur if ref == "latest" else img_prev)

        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")
            report_path = os.path.join(tmp, "report.md")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump({"image": "ghcr.io/secureblue/x", "arch": "amd64", "tag": "latest",
                           "digest": prev_dig, "index_digest": prev_idx,
                           "created": img_prev["created"], "analysis_incomplete": False}, fh)
            pa = S.PackageTable({"curl": pkg("curl", "8.20.0-1.fc45")})
            pb = S.PackageTable({"curl": pkg("curl", "8.21.0-1.fc45")})
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=fake_resolve), \
                    patch.object(S, "load_pkglist", side_effect=[pa, pb]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "secureblue/x", "--state", state_path,
                             "--report", report_path, "--scan", "0", "--no-bodhi",
                             "--no-audit", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            self.assertEqual(seen, ["latest", prev_idx, prev_dig])


if __name__ == "__main__":
    unittest.main()
