"""Output-file framing must keep image metadata out of workflow commands."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


def parse_outputs(text):
    """Parse the runner's name=value / name<<delimiter framing (LF fixtures)."""
    lines = iter(text.split("\n"))
    result = {}
    for line in lines:
        if not line:
            continue
        equal, heredoc = line.find("="), line.find("<<")
        if heredoc >= 0 and (equal < 0 or heredoc < equal):
            name, delimiter = line.split("<<", 1)
            value = []
            for entry in lines:
                if entry == delimiter:
                    break
                value.append(entry)
            else:
                raise AssertionError("unterminated output")
            result[name] = "\n".join(value)
        else:
            name, value = line.split("=", 1)
            result[name] = value
    return result


class TestOutputBoundaries(unittest.TestCase):
    def _write(self, pairs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outputs"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(path)}):
                S.gh_outputs(pairs)
            return path.read_bytes().decode("utf-8")

    def test_old_delimiter_in_metadata_cannot_overwrite_the_verdict(self):
        value = "notes\nEOF_SBWATCH\nverdict=skip\nsummary<<EOF_SBWATCH\nmore"
        outputs = parse_outputs(self._write({"verdict": "update-now", "summary": value}))
        self.assertEqual(outputs, {"verdict": "update-now", "summary": value})

    def test_generated_delimiter_collision_is_retried(self):
        value = "before\nEOF_SBWATCH_collision\nafter"
        with patch.object(S.secrets, "token_hex", side_effect=["collision", "safe"]) as token:
            raw = self._write({"summary": value})
        self.assertEqual(token.call_count, 2)
        self.assertEqual(parse_outputs(raw), {"summary": value})
        self.assertIn("summary<<EOF_SBWATCH_safe\n", raw)

    def test_unicode_empty_values_and_trailing_newlines_roundtrip(self):
        pairs = {"verdict": "consider", "summary": "中文\n\nsecond line\n", "empty": "", "count": 7}
        self.assertEqual(parse_outputs(self._write(pairs)), dict(pairs, count="7"))

    def test_values_are_stringified_before_testing_for_newlines(self):
        class Text:
            def __str__(self):
                return "first\nverdict=skip"
        self.assertEqual(parse_outputs(self._write({"verdict": "update-now", "summary": Text()})),
                         {"verdict": "update-now", "summary": "first\nverdict=skip"})

    def test_carriage_returns_use_delimited_output(self):
        raw = self._write({"summary": "first\rsecond"})
        self.assertTrue(raw.startswith("summary<<"))
        self.assertEqual(parse_outputs(raw), {"summary": "first\rsecond"})

    def test_workflow_passes_verdicts_as_data_not_shell_source(self):
        workflow = (Path(S.__file__).parent / ".github/workflows/sbwatch.yml").read_text()
        self.assertNotIn('"${{ steps.check.outputs.verdict }}"', workflow)
        self.assertNotIn('"${{ steps.notify.outputs.verdict }}"', workflow)
        self.assertIn('verdict="$VERDICT"', workflow)


if __name__ == "__main__":
    unittest.main()
