"""A successful HTTP query cannot repair a missing RPM header."""
import unittest
from test_sbwatch import S, FakeBodhi, pkg


class TestBacklogInventoryCoverage(unittest.TestCase):
    def test_damaged_inventory_marks_coverage_as_partial(self):
        pkgs = S.PackageTable({"dnf5": pkg("dnf5", "5.4.8.0-2.fc45")})
        pkgs.headers_rejected = 1
        _, cov = S.security_backlog(pkgs, "F45", FakeBodhi({}))
        self.assertFalse(cov["rpmdb_complete"])
        self.assertEqual(cov["rpmdb_issues"]["headers_rejected"], 1)
        self.assertIn("RPM inventory incomplete", S.coverage_line(cov).en)

    def test_empty_inventory_is_not_complete(self):
        _, cov = S.security_backlog({}, "F45", FakeBodhi({}))
        self.assertTrue(cov["rpmdb_issues"]["empty_table"])
        self.assertFalse(cov["rpmdb_complete"])
