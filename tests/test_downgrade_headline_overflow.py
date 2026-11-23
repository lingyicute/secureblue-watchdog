"""The downgrade warning's overflow marker counts source packages, not binaries."""
import unittest

from test_downgrade_headline import LD
from test_sbwatch import S, pkg

NAMES = ["nano", "vim", "less", "grep", "sed"]


class TestDowngradeHeadlineOverflow(unittest.TestCase):
    def test_marker_names_the_unit_it_counts(self):
        old = {n: pkg(n, "2.0-1.fc45") for n in NAMES}
        new = {n: pkg(n, "1.0-1.fc45") for n in NAMES}
        d = S.pkg_diff(old, new)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
        v = S.verdict_of(d, LD, {}, {})
        self.assertIn("(+2 more source package(s) not shown)", v["headline"])
        self.assertNotIn("(+2 more not shown)", v["headline"])
        self.assertIn("（另有 2 个源码包未显示）", v["headline_zh"])
        shown = v["headline"].split("downgrades ", 1)[1]
        self.assertEqual(shown.count(" → "), 3)

    def test_no_marker_when_everything_fits(self):
        d = S.pkg_diff({"nano": pkg("nano", "2.0-1.fc45")}, {"nano": pkg("nano", "1.0-1.fc45")})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", None)
        v = S.verdict_of(d, LD, {}, {})
        self.assertNotIn("not shown", v["headline"])


    def test_per_source_binary_overflow_names_unit_and_uses_chinese_joiner(self):
        bins = ("kernel", "kernel-core", "kernel-modules")
        old = {b: pkg(b, "7.3.4-300.fc45", src="kernel") for b in bins}
        new = {b: pkg(b, "7.3.3-300.fc45", src="kernel") for b in bins}
        d = S.pkg_diff(old, new)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
        v = S.verdict_of(d, LD, {}, {})
        self.assertIn("(+1 more binary package(s) not shown)", v["headline"])
        self.assertIn("（另有 1 个二进制包未显示）", v["headline_zh"])
        warn_zh = v["headline_zh"].split("警告：此次更新会降级 ", 1)[1]
        self.assertNotIn("), ", warn_zh)


if __name__ == "__main__":
    unittest.main()
