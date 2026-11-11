"""Regressions for Bodhi erratum CVE reconciliation and backlog aggregation."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S, FakeBodhi, pkg


class TestErrataAndBacklog(unittest.TestCase):
    def test_erratum_cve_removes_false_dropped_cve_and_marks_security(self):
        old_pkg = pkg("foo", "1.0-1.fc45", changelog=[
            {"time": 10, "who": "dev", "text": "- Fix CVE-2026-9999"}])
        new_pkg = pkg("foo", "1.1-1.fc45", changelog=[
            {"time": 20, "who": "dev", "text": "- Rebase to 1.1"}])
        bodhi = FakeBodhi({"foo": [{
            "alias": "FEDORA-2026-bugfixcve", "type": "bugfix", "severity": "low",
            "status": "stable", "nvrs": ["foo-1.1-1.fc45"],
            "notes": "Includes CVE-2026-9999 fix", "bugs": [], "cves": ["CVE-2026-9999"]
        }]})
        info = S.classify_change(old_pkg, new_pkg, "F45", bodhi)
        self.assertTrue(info["security"])
        self.assertEqual(info["cves"], ["CVE-2026-9999"])
        self.assertEqual(info["cves_dropped"], [])
        self.assertFalse(any("no longer mentioned" in w for w in info["why"]))

    def test_backlog_aggregates_newest_build_highest_severity_and_all_cves(self):
        pkgs = {"openssl": pkg("openssl", "3.2.0-1.fc45", src="openssl")}
        bodhi = FakeBodhi({"openssl": [
            {"alias": "FEDORA-2026-low", "type": "security", "severity": "low",
             "status": "stable", "nvrs": ["openssl-3.2.2-1.fc45"],
             "notes": "minor fix", "bugs": [], "cves": ["CVE-2026-2222"]},
            {"alias": "FEDORA-2026-urgent", "type": "security", "severity": "urgent",
             "status": "stable", "nvrs": ["openssl-3.2.1-1.fc45"],
             "notes": "critical fix", "bugs": [], "cves": ["CVE-2026-1111"]},
        ]})
        rows, _ = S.security_backlog(pkgs, "F45", bodhi, limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["want"], "3.2.2-1.fc45")
        self.assertEqual(rows[0]["severity"], "urgent")
        self.assertEqual(rows[0]["cves"], ["CVE-2026-1111", "CVE-2026-2222"])

    def test_bodhi_malformed_json_payload_counts_as_failed_lookup(self):
        bodhi = S.Bodhi(cache_dir=None, sleep=0, max_calls=3)
        with patch.object(S.urllib.request, "urlopen",
                          return_value=io.BytesIO(b'["not", "a", "dict"]')),                 contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bodhi.updates_for_src("kernel", "F45"), [])
        self.assertEqual(bodhi.failed, 1)


if __name__ == "__main__":
    unittest.main()
