"""A missing epoch and an explicit epoch 0 are the same epoch."""
import unittest

from test_sbwatch import S, pkg


class TestEpochSpelling(unittest.TestCase):
    def test_a_missing_epoch_and_an_explicit_zero_are_one_epoch(self):
        for before, after in (("", "0"), ("0", ""), ("", 0), (0, "0")):
            with self.subTest(before=before, after=after):
                d = S.pkg_diff({"foo": pkg("foo", "1.2-3.fc44", epoch=before)},
                               {"foo": pkg("foo", "1.2-3.fc44", epoch=after)})
                # not even a "rebuild": nothing about the package moved
                self.assertEqual(d["changed"], [])
                self.assertEqual(d["unchanged_count"], 1)

    def test_a_real_epoch_change_is_still_a_change(self):
        for before, after, direction in (("", "1", "upgrade"), ("0", "1", "upgrade"),
                                         ("2", "", "downgrade")):
            with self.subTest(before=before, after=after):
                d = S.pkg_diff({"foo": pkg("foo", "1.2-3.fc44", epoch=before)},
                               {"foo": pkg("foo", "1.2-3.fc44", epoch=after)})
                self.assertEqual([c["dir"] for c in d["changed"]], [direction])


if __name__ == "__main__":
    unittest.main()
