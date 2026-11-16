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

    def test_json_diff_output_names_both_epochs_when_epoch_moves(self):
        import contextlib, io, json, tempfile
        from pathlib import Path
        from unittest.mock import patch
        old = pkg("foo", "1.2-3.fc44", epoch="")
        new = pkg("foo", "1.2-3.fc44", epoch="1")
        res = {"a": {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []},
               "b": {"ref": "b", "digest": "sha256:" + "b" * 64, "annotations": {}, "layers": []},
               "diff": S.pkg_diff({"foo": old}, {"foo": new}),
               "layers": S.layer_diff({"layers": []}, {"layers": []}),
               "verdict": S.verdict_of(S.pkg_diff({"foo": old}, {"foo": new}),
                                       S.layer_diff({"layers": []}, {"layers": []}), {}, {}),
               "notes": [], "xc": {"versions_known": True, "silent_rebuilds": []}}
        with tempfile.TemporaryDirectory() as td:
            out = f"{td}/diff.json"
            with patch.object(S, "do_diff", return_value=res),                     contextlib.redirect_stdout(io.StringIO()):
                S.main(["diff", "a", "b", "--json-out", out])
            item = json.loads(Path(out).read_text(encoding="utf-8"))["changed"][0]
        self.assertEqual((item["old"], item["new"]), ("0:1.2-3.fc44", "1:1.2-3.fc44"))


if __name__ == "__main__":
    unittest.main()
