"""The label a report gives the baseline that came from the state file."""
import unittest

from test_sbwatch import S

DIGEST = "sha256:" + "a" * 64


class TestStateLabel(unittest.TestCase):
    def test_builds_sharing_one_version_string_are_told_apart(self):
        # secureblue pushes several builds a day, all carrying the same version
        first = S._state_label({"digest": DIGEST, "version": "45.20261111.0",
                                "created": "2026-11-11T03:51:37Z"})
        second = S._state_label({"digest": DIGEST, "version": "45.20261111.0",
                                 "created": "2026-11-11T13:02:10Z"})
        self.assertEqual(first, "45.20261111.0 @ 2026-11-11T03:51:37")
        self.assertNotEqual(first, second)

    def test_it_falls_back_to_whatever_the_state_holds(self):
        self.assertEqual(S._state_label({"digest": DIGEST, "version": "?",
                                         "created": "2026-11-11T03:51:37Z"}),
                         "2026-11-11T03:51:37")
        self.assertEqual(S._state_label({"digest": DIGEST, "version": "45.1"}), "45.1")
        # a digest stays whole, so that shortref() can abbreviate it in the title
        self.assertEqual(S._state_label({"digest": DIGEST}), DIGEST)
        self.assertEqual(S.shortref(S._state_label({"digest": DIGEST})),
                         "sha256:aaaaaaaaaaaa…")


if __name__ == "__main__":
    unittest.main()
