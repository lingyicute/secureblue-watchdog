"""A CVE id that leaves the changelog of a *downgraded* package is a reverted fix."""
import unittest

from test_sbwatch import S, pkg

FIX = {"time": 2, "who": "a", "text": "Fix CVE-2026-123177"}
BASE = {"time": 1, "who": "a", "text": "Initial build"}


def image(n):
    return {"ref": f"r{n}", "digest": "sha256:" + str(n) * 64, "annotations": {}, "created": ""}


def report(old, new):
    diff = S.pkg_diff({"dnf5": old}, {"dnf5": new})
    for c in diff["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
    layers = S.layer_diff({"layers": []}, {"layers": []})
    xc = S.crosscheck_chunks(layers, diff)
    groups = S.group_by_src(diff["changed"])
    verdict = S.verdict_of(diff, layers, {}, xc, groups=groups)
    md = S.render_markdown("t", image(1), image(2), diff, layers, verdict, [], xc, None, groups)
    return verdict, md


class TestDowngradeRevertedCves(unittest.TestCase):
    def test_a_downgrade_reverts_the_fix(self):
        # the live rollback latest -> 45.20261114.0: dnf5 5.4.8.0-2 -> 5.4.7.0-1
        verdict, md = report(pkg("dnf5", "5.4.8.0-2.fc45", changelog=[FIX, BASE]),
                             pkg("dnf5", "5.4.7.0-1.fc45", changelog=[BASE]))
        self.assertEqual(verdict["cves_dropped"], ["CVE-2026-123177"])
        self.assertEqual(verdict["cves_reverted"], ["CVE-2026-123177"])
        self.assertIn("the downgrade most likely reverts these fixes", verdict["headline"])
        self.assertIn("降级很可能回退了这些修复", verdict["headline_zh"])
        self.assertNotIn("usually a changelog edit", verdict["headline"])
        self.assertNotIn("通常是更新日志被编辑，而非修复被移除", verdict["headline_zh"])
        self.assertIn("- `dnf5`: no longer mentions CVE-2026-123177 — this package is "
                      "downgraded, which most likely reverts: CVE-2026-123177", md)
        self.assertIn("——该包被降级，很可能回退了：CVE-2026-123177", md)

    def test_a_trimmed_changelog_of_an_upgrade_stays_a_hint(self):
        verdict, md = report(pkg("dnf5", "5.4.7.0-1.fc45", changelog=[FIX, BASE]),
                             pkg("dnf5", "5.4.8.0-2.fc45", changelog=[BASE]))
        self.assertEqual(verdict["cves_dropped"], ["CVE-2026-123177"])
        self.assertEqual(verdict["cves_reverted"], [])
        self.assertIn("usually a changelog edit", verdict["headline"])
        self.assertNotIn("most likely reverts", verdict["headline"] + md)
        self.assertNotIn("回退了", verdict["headline_zh"])


if __name__ == "__main__":
    unittest.main()
