"""A rollback that also moves a same-version chunk is not headlined as skippable."""
import unittest

from test_downgrade_headline import LD
from test_sbwatch import S, pkg


class TestRollbackWithSilentChunk(unittest.TestCase):
    def test_rollback_with_same_version_chunk_is_not_called_skippable(self):
        d = S.pkg_diff({"nano": pkg("nano", "8.2-1.fc45")},
                       {"nano": pkg("nano", "8.1-1.fc45")})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", None)
        xc = {"non_package_chunks": [], "non_package_bytes": 0, "versions_known": True,
              "silent_rebuilds": [("glibc", 100)]}
        v = S.verdict_of(d, LD, {}, xc)
        self.assertEqual(v["level"], "consider")
        self.assertIn("glibc", v["headline"])
        self.assertIn("1 source package (1 binary) downgraded", v["headline"])
        self.assertIn("WARNING: this update downgrades nano", v["headline"])
        self.assertNotIn("Reasonable to skip", v["headline"])
        self.assertIn("1 个源码包（1 个二进制包）被降级", v["headline_zh"])
        self.assertNotIn("可以合理地跳过", v["headline_zh"])


if __name__ == "__main__":
    unittest.main()
