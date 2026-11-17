"""--report must work outside Actions and failures must not advance watch state."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S
from test_check_state import _image


class TestCheckEarlyReports(unittest.TestCase):
    def run_check(self, directory, seen=False):
        state, report = Path(directory) / "state.json", Path(directory) / "nested/report.md"
        current = _image(2)
        if seen:
            state.write_text(json.dumps({"digest": current["digest"], "last_verdict": "consider"}))
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "resolve", return_value=dict(current, ref="latest")), \
                patch.object(S, "tag_exists", return_value=None), \
                patch.dict(os.environ, {}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            S.main(["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                    "--report", str(report), "--cache-dir", directory])
        return state, report

    def test_local_unknown_report_and_json_are_written(self):
        with tempfile.TemporaryDirectory() as directory:
            _, report = self.run_check(directory)
            self.assertIn("No baseline", report.read_text())
            self.assertEqual(json.loads(Path(str(report) + ".json").read_text())["verdict"]["level"], "unknown")

    def test_no_update_replaces_the_previous_report(self):
        with tempfile.TemporaryDirectory() as directory:
            _, report = self.run_check(directory, seen=True)
            self.assertIn("No new build", report.read_text())
            self.assertEqual(json.loads(Path(str(report) + ".json").read_text())["verdict"]["level"], "no-update")

    def test_failed_report_write_is_fatal_and_does_not_advance_state(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(S, "_atomic_write_text", side_effect=PermissionError("read-only")):
                with self.assertRaises(PermissionError):
                    self.run_check(directory)
            self.assertFalse((Path(directory) / "state.json").exists())


if __name__ == "__main__":
    unittest.main()
