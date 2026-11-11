"""CVE membership depends on retained entries, not only changed entries."""
import types
import unittest
from unittest.mock import patch

from test_sbwatch import S, FakeBodhi, pkg


COMMON = {"time": 1, "who": "maintainer", "text": "Fix CVE-2026-12345"}
REPEATED = {"time": 2, "who": "maintainer", "text": "Document CVE-2026-12345"}


class TestRetainedCves(unittest.TestCase):
    def _info(self, old_log, new_log, bodhi=None):
        return S.classify_change(pkg("example", "1-1.fc45", changelog=old_log),
                                 pkg("example", "2-1.fc45", changelog=new_log), "F45", bodhi)

    def test_repeating_a_retained_cve_is_not_a_new_fix(self):
        info = self._info([COMMON], [REPEATED, COMMON])
        self.assertEqual(info["cves"], [])
        self.assertFalse(info["security"])

    def test_removing_one_mention_does_not_drop_a_retained_cve(self):
        info = self._info([REPEATED, COMMON], [COMMON])
        self.assertEqual(info["cves_dropped"], [])

    def test_identical_duplicate_entries_do_not_change_cve_membership(self):
        for old, new in (([COMMON], [COMMON, COMMON]), ([COMMON, COMMON], [COMMON])):
            with self.subTest(old_count=len(old)):
                info = self._info(old, new)
                self.assertEqual(info["cves"], [])
                self.assertEqual(info["cves_dropped"], [])

    def test_genuine_new_and_dropped_ids_still_survive(self):
        old = [COMMON, dict(REPEATED, text="CVE-2026-12345 CVE-2025-11111")]
        new = [COMMON, dict(REPEATED, text="CVE-2026-12345 CVE-2026-22222")]
        info = self._info(old, new)
        self.assertEqual(info["cves"], ["CVE-2026-22222"])
        self.assertEqual(info["cves_dropped"], ["CVE-2025-11111"])

    def test_independent_new_advisory_evidence_is_not_suppressed(self):
        bodhi = FakeBodhi({"example": [{"alias": "FEDORA-2026-test", "type": "security",
                    "severity": "high", "status": "stable", "nvrs": ["example-2-1.fc45"],
                    "notes": "CVE-2026-12345", "bugs": [], "cves": []}]})
        info = self._info([COMMON], [REPEATED, COMMON], bodhi)
        self.assertTrue(info["has_security_erratum"])
        self.assertTrue(info["security"])
        self.assertEqual(info["cves"], ["CVE-2026-12345"])

    def test_retained_entry_scan_is_bounded_and_disclosed_in_the_report(self):
        retained = [dict(COMMON, time=3, text="routine change"), COMMON]
        old = S.PackageTable({"example": pkg("example", "1-1.fc45", changelog=retained)})
        new = S.PackageTable({"example": pkg("example", "2-1.fc45", changelog=[REPEATED] + retained)})
        args = types.SimpleNamespace(exact=1, keep_order=True, cache_dir="unused",
                                     no_bodhi=True, max_bodhi=0, audit=False)
        a = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        b = dict(a, ref="b", digest="sha256:" + "b" * 64)
        with patch.object(S, "RETAINED_LOG_CAP", 1, create=True), \
                patch.object(S, "load_pkglist", side_effect=[old, new]):
            result = S.do_diff(args, "a", "b", images=(a, b),
                               reg=types.SimpleNamespace(_token=lambda: None))
        scan = result["diff"]["changed"][0]["cls"]["changelog_scan"]
        self.assertEqual(scan["retained_total"], 2)
        self.assertEqual(scan["retained_scanned"], 1)
        self.assertTrue(any("retained" in str(note) and "partially read" in str(note)
                            for note in result["notes"]))


if __name__ == "__main__":
    unittest.main()
