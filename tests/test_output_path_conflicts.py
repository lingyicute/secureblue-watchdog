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
