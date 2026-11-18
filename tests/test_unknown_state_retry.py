"""An inconclusive watch must not become a healthy no-update on the next run."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, pkg
from test_check_state import _image


class TestUnknownStateRetry(unittest.TestCase):
    def test_same_digest_is_retried_until_a_baseline_is_available(self):
        previous, current = _image(1), _image(2)
        available = False
        def resolve(reg, ref, light=False):
            return dict(current if ref == "latest" else previous, ref=ref)
        def packages(reg, img, ref, directory, notes):
            return S.PackageTable({"trivalent": pkg("trivalent", img["annotations"]["org.opencontainers.image.version"] + ".0-1.fc45")})
        with tempfile.TemporaryDirectory() as directory:
            state, output = Path(directory) / "state.json", Path(directory) / "output"
            argv = ["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                    "--report", str(Path(directory) / "report.md"), "--cache-dir", directory,
                    "--no-fast", "--no-audit", "--no-bodhi", "--prune-days", "0"]
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S, "tag_exists", side_effect=lambda *a, **k: previous["digest"] if available else None), \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                for _ in range(2):
                    output.write_text("")
                    self.assertEqual(S.main(argv), 0)
                    self.assertIn("verdict=unknown\n", output.read_text())
                    self.assertEqual(json.loads(state.read_text())["last_verdict"], "unknown")
                available = True
                output.write_text("")
                self.assertEqual(S.main(argv), 0)
                self.assertIn("verdict=update-now\n", output.read_text())
                self.assertEqual(json.loads(state.read_text())["prev_digest"], previous["digest"])
                output.write_text("")
                self.assertEqual(S.main(argv), 0)
                self.assertIn("verdict=no-update\n", output.read_text())

    def test_new_tag_after_unknown_still_compares_last_usable_baseline(self):
        old, incomplete, new = (_image(n) for n in (1, 2, 3))
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            report = Path(directory) / "report.md"
            state.write_text(json.dumps({"digest": incomplete["digest"], "last_verdict": "unknown",
                                         "prev_digest": old["digest"], "prev_label": "last usable"}))
            imgs = {old["digest"]: old, incomplete["digest"]: incomplete, "latest": new}
            with patch.object(S.Registry, "_token", return_value=None),                     patch.object(S, "resolve", side_effect=lambda r, ref: dict(imgs[ref], ref=ref)),                     patch.object(S, "load_pkglist", side_effect=lambda r, img, *a: S.PackageTable(
                        {"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc45")})),                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory, "--no-fast",
                             "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            payload = json.loads(Path(str(report) + ".json").read_text())
            self.assertEqual(payload["from_digest"], old["digest"])
            self.assertEqual(payload["digest"], new["digest"])


if __name__ == "__main__":
    unittest.main()
