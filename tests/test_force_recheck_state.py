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

    def test_force_recheck_keeps_the_baseline_label_check_wrote_itself(self):
        # a baseline picked from the build history is labelled in 35 characters
        label = "45.20261110.0 @ 2026-11-10T21:50:50"

        def image(n):
            digest = "sha256:" + str(n) * 64
            return {"digest": digest, "index_digest": digest,
                    "created": f"2026-11-1{n}T00:00:00Z", "layers": [],
                    "annotations": {"org.opencontainers.image.version": f"45.2026111{n}.0"}}

        prev, cur = image(0), image(1)

        def resolve(reg, ref, light=False):
            return dict(cur if ref in ("latest", cur["digest"]) else prev, ref=ref)

        def packages(reg, img, ref, directory, notes):
            return S.PackageTable({"bash": pkg("bash", "5.3-1.fc45")})

        with tempfile.TemporaryDirectory() as directory:
            state, report = Path(directory) / "state.json", Path(directory) / "report.md"
            state.write_text(json.dumps({"digest": cur["digest"], "created": cur["created"],
                                         "prev_digest": prev["digest"], "prev_label": label}))
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                for _ in range(2):      # the second run reads back what the first one saved
                    rc = S.main(["check", "--image", "x/y", "--state", str(state),
                                 "--report", str(report), "--cache-dir", directory,
                                 "--scan", "0", "--force", "--no-fast", "--no-audit",
                                 "--no-bodhi", "--prune-days", "0"])
                    self.assertEqual(rc, 0)
            self.assertEqual(json.loads(Path(str(report) + ".json").read_text())["from"], label)
            self.assertEqual(json.loads(state.read_text())["prev_label"], label)
            self.assertIn(f"{label} -> latest", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
