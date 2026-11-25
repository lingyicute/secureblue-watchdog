import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sbwatch as S  # noqa: E402


class TestCveIdBoundary(unittest.TestCase):
    def test_overlong_number_is_not_cut_to_another_id(self):
        """CVE-2026-12345678 is not CVE-2026-1234567."""
        self.assertEqual(S.find_cves("see CVE-2026-12345678"), ["CVE-2026-12345678"])
        longest = "CVE-2026-" + "9" * 19
        self.assertEqual(S.find_cves(longest), [longest])
        self.assertEqual(S.find_cves(longest + "0"), [])

    def test_cve_record_identifiers_use_ascii_digits(self):
        self.assertEqual(S.find_cves("CVE-２０２６-1234 CVE-2026-１２３４"), [])

    def test_regular_ids_still_match(self):
        self.assertEqual(S.find_cves("CVE-2026-1234567, CVE 2026-114583; CVE-2024-4741."),
                         ["CVE-2026-1234567", "CVE-2026-114583", "CVE-2024-4741"])


    def test_alphanumeric_prefix_before_cve_is_not_matched(self):
        self.assertEqual(S.find_cves("nocve-2026-1234 abcve2026-5678 0cve-2026-9999"), [])
        self.assertEqual(S.find_cves("(CVE-2026-1234),CVE-2026-5678"),
                         ["CVE-2026-1234", "CVE-2026-5678"])

    def test_brace_listed_cves_expand_valid_ascii_ids(self):
        text = "- Rebuild for rust-openssl CVE-2026-{41676,41677, 41678}"
        self.assertEqual(S.find_cves(text),
                         ["CVE-2026-41676", "CVE-2026-41677", "CVE-2026-41678"])
        self.assertEqual(S.find_cves("CVE-2026-{1234," + "9" * 20 + "}"), ["CVE-2026-1234"])
        self.assertEqual(S.find_cves("nocve-2026-{1234,5678} CVE-2026-{１２３４,5678}"), [])


if __name__ == "__main__":
    unittest.main()
