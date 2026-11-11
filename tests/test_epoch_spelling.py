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

class TestChangedEpochIsShown(unittest.TestCase):
    def _group(self, before, after):
        d = S.pkg_diff({"foo": before}, {"foo": after})
        return d, S.group_by_src(d["changed"])[0]

    def test_an_epoch_only_change_is_not_shown_as_identical_versions(self):
        _d, g = self._group(pkg("foo", "1.2-3.fc44", epoch=""), pkg("foo", "1.2-3.fc44", epoch="1"))
        self.assertEqual((g["old_evr"], g["new_evr"]), ("0:1.2-3.fc44", "1:1.2-3.fc44"))

    def test_a_bump_inside_one_epoch_keeps_its_bare_evr(self):
        _d, g = self._group(pkg("foo", "1.2-3.fc44", epoch="1"), pkg("foo", "1.3-1.fc44", epoch="1"))
        self.assertEqual((g["old_evr"], g["new_evr"]), ("1.2-3.fc44", "1.3-1.fc44"))

    def test_the_report_names_both_epochs(self):
        d, _g = self._group(pkg("foo", "1.2-3.fc44", epoch=""), pkg("foo", "1.2-3.fc44", epoch="1"))
        a = {"ref": "A", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        ld = S.layer_diff(a, a)
        md = S.render_markdown("t", a, a, d, ld, S.verdict_of(d, ld, {}, {}), [])
        self.assertIn("0:1.2-3.fc44 → 1:1.2-3.fc44", md)


if __name__ == "__main__":
    unittest.main()
