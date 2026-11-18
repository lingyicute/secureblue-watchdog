"""A rollback is not headlined as routine churn."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}


def verdict(old, new):
    d = S.pkg_diff(old, new)
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
    return S.verdict_of(d, LD, {}, {})


class TestRollbackHeadline(unittest.TestCase):
    def test_a_rollback_names_the_downgrades_first(self):
        # the live tag moved back from 45.20261117.0 to 45.20261116.0
        v = verdict({"gjs": pkg("gjs", "1.90.1-2.fc45"), "ibus": pkg("ibus", "1.5.35-2.fc45"),
                     "ibus-gtk3": pkg("ibus-gtk3", "1.5.35-2.fc45", src="ibus"),
                     "nano": pkg("nano", "8.1-1.fc45")},
                    {"gjs": pkg("gjs", "1.90.1-1.fc45"), "ibus": pkg("ibus", "1.5.35-1.fc45"),
                     "ibus-gtk3": pkg("ibus-gtk3", "1.5.35-1.fc45", src="ibus"),
                     "nano": pkg("nano", "8.2-1.fc45")})
        self.assertEqual(v["level"], "consider")
        self.assertTrue(v["headline"].startswith(
            "2 source packages (3 binary) downgraded, 1 source package (1 binary) bumped, "
            "0 added / 0 removed, no CVE and no security erratum among the upgrades"),
            v["headline"])
        self.assertTrue(v["headline_zh"].startswith(
            "2 个源码包（3 个二进制包）被降级，1 个源码包（1 个二进制包）升级，"
            "新增 0 个 / 移除 0 个，升级部分无 CVE、无安全勘误"), v["headline_zh"])
        self.assertNotIn("routine churn", v["headline"])
        self.assertNotIn("常规更新", v["headline_zh"])

    def test_plain_upgrades_are_still_routine_churn(self):
        v = verdict({"nano": pkg("nano", "8.1-1.fc45")}, {"nano": pkg("nano", "8.2-1.fc45")})
        self.assertEqual(v["level"], "skip")
        self.assertTrue(v["headline"].startswith(
            "routine churn: 1 source package (1 binary) bumped, 0 added / 0 removed, "
            "no CVE and no security erratum"), v["headline"])
        self.assertNotIn("among the upgrades", v["headline"])
        self.assertTrue(v["headline_zh"].startswith("常规更新：1 个源码包（1 个二进制包）升级，"),
                        v["headline_zh"])


if __name__ == "__main__":
    unittest.main()
