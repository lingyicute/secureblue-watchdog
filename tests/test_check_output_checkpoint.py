"""Do not acknowledge a transition until every requested output is written."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, pkg
from test_check_state import _image


class TestOutputCheckpoint(unittest.TestCase):
    def test_full_analysis_output_error_preserves_previous_state(self):
        old, new = _image(1), _image(2)
        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            before = json.dumps({"digest": old["digest"], "last_verdict": "consider"})
            state.write_text(before)
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=lambda reg, ref, **k: dict(
                        new if ref == "latest" else old, ref=ref)), \
                    patch.object(S, "load_pkglist", return_value=S.PackageTable({"bash": pkg("bash", "5-1.fc45")})), \
                    patch.object(S, "gh_outputs", side_effect=OSError("CI output unavailable")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(OSError, "CI output unavailable"):
                    S.main(["check", "--state", str(state), "--report", str(report), "--scan", "0",
                            "--no-fast", "--no-bodhi", "--no-audit", "--prune-days", "0"])
            self.assertTrue(Path(str(report) + ".json").exists())
            self.assertEqual(state.read_text(), before)
