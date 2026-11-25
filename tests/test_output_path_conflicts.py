"""A checkpoint or one output format must never replace another report."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sbwatch as S


class TestOutputPathConflicts(unittest.TestCase):
    def _reject(self, argv):
        with patch.object(S, "_registry") as registry, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as ex:
                S.main(argv)
            self.assertEqual(ex.exception.code, 2)
            self.assertIn("different output paths", err.getvalue())
            registry.assert_not_called()

    def test_symlinked_state_cannot_replace_the_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "watch.md"
            state = Path(tmp) / "state.json"
            state.symlink_to(report.with_suffix(".md.json"))
            self._reject(["check", "--state", str(state), "--report", str(report)])

    def test_diff_formats_cannot_share_a_file(self):
        self._reject(["diff", "a", "b", "--markdown", "same", "--json-out", "./same"])

    def test_diff_json_dash_cannot_share_redirected_stdout_file_with_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "both.out"
            with out.open("w", encoding="utf-8") as fh, patch.object(S.sys, "stdout", fh):
                self._reject(["diff", "a", "b", "--markdown", str(out), "--json-out", "-"])

    def test_stdout_report_cannot_share_redirected_file_with_json_output(self):
        for argv_fn in (
            lambda p: ["diff", "a", "b", "--json-out", str(p)],
            lambda p: ["layers", "a", "b", "--json", str(p)],
            lambda p: ["backlog", "latest", "--json-out", str(p)],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "same.out"
                with out.open("w", encoding="utf-8") as fh, patch.object(S.sys, "stdout", fh):
                    self._reject(argv_fn(out))
