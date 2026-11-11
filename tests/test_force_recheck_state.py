"""`check --force` on an unchanged tag must reuse `prev_digest` and keep direction."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestForceRecheckState(unittest.TestCase):
    def test_force_recheck_reuses_prev_digest_and_preserves_rollback_direction(self):
        def image(version):
            digest = "sha256:" + str(version) * 64
            return {"digest": digest, "index_digest": digest,
                    "created": f"2026-01-0{version}T00:00:00Z", "layers": [],
                    "annotations": {"org.opencontainers.image.version": str(version)}}

        older, newer = image(1), image(2)

        def resolve(reg, ref, light=False):
            return dict(older if ref in ("latest", older["digest"]) else newer, ref=ref)

        def packages(reg, img, ref, directory, notes):
            version = img["annotations"]["org.opencontainers.image.version"]
            log = [{"time": 2, "text": "Fix CVE-2026-12345"}] if version == "2" else []
            return S.PackageTable({"trivalent": pkg("trivalent", version + ".0-1.fc45",
                                                    changelog=log)})

        with tempfile.TemporaryDirectory() as directory:
            state, report = Path(directory) / "state.json", Path(directory) / "report.md"
            # Simulate state after a rollback from 2 -> 1 was already recorded
            state.write_text(json.dumps({
                "digest": older["digest"],
                "prev_digest": newer["digest"],
                "prev_label": "2",
                "version": "1",
                "created": older["created"],
            }))
            with patch.object(S.Registry, "_token", return_value=None),                     patch.object(S, "resolve", side_effect=resolve),                     patch.object(S, "load_pkglist", side_effect=packages),                     contextlib.redirect_stdout(io.StringIO()),                     contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory,
                             "--scan", "0", "--force", "--no-fast", "--no-audit",
                             "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            result = json.loads(Path(str(report) + ".json").read_text())
            saved = json.loads(state.read_text())
            self.assertEqual(result["changed"][0]["dir"], "downgrade")
            self.assertEqual(result["verdict"]["level"], "consider")
            self.assertEqual(saved["digest"], older["digest"])
            self.assertEqual(saved["prev_digest"], newer["digest"])


if __name__ == "__main__":
    unittest.main()
