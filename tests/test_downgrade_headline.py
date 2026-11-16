"""Downgrades are never reported as forward kernel or routine bumps."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}


class TestDowngradeHeadline(unittest.TestCase):
    def test_kernel_downgrade_with_changed_ostree_linux_is_not_a_kernel_bump(self):
        d = S.pkg_diff({"kernel": pkg("kernel", "7.3.3-300.fc45")},
                       {"kernel": pkg("kernel", "7.3.2-300.fc45")})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", None)
        v = S.verdict_of(d, LD, {"kernel_a": "7.3.3-300.fc45.x86_64",
                                 "kernel_b": "7.3.2-300.fc45.x86_64",
                                 "kernel_pkg_unchanged": False}, {})
        self.assertEqual(v["level"], "consider")
        self.assertFalse(v["kernel_changed"])
        self.assertNotIn("the kernel moved", v["level_basis"])
        self.assertNotIn("Reasonable to skip", v["headline"])
        self.assertIn("downgrades kernel", v["headline"])


if __name__ == "__main__":
    unittest.main()
