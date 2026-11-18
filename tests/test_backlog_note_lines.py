"""Blank lines in an erratum's notes are not hidden text."""
import unittest

from test_sbwatch import S


class TestBacklogNoteLines(unittest.TestCase):
    def test_trailing_blank_lines_are_not_counted(self):
        # FEDORA-2026-b9a53ff63c, as Bodhi serves it
        notes = "Update for dnf5-5.4.8.0-1.fc45. It also fixes CVE-2026-123177.\n\n"
        self.assertEqual(S._note_head(notes),
                         ("Update for dnf5-5.4.8.0-1.fc45. It also fixes CVE-2026-123177.", 0))

    def test_further_text_is_still_counted(self):
        self.assertEqual(S._note_head("\nfirst\n\nsecond\nthird\n"), ("first", 2))

    def test_empty_notes(self):
        for notes in ("", "\n \n", None):
            self.assertEqual(S._note_head(notes), ("", 0))


if __name__ == "__main__":
    unittest.main()
