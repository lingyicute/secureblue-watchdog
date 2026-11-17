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


if __name__ == "__main__":
    unittest.main()
