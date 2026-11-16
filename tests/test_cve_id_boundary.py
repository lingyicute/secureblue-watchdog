import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sbwatch as S  # noqa: E402


class TestCveIdBoundary(unittest.TestCase):
    def test_overlong_number_is_not_cut_to_another_id(self):
        """CVE-2026-12345678 is not CVE-2026-1234567."""
        self.assertEqual(S.find_cves("see CVE-2026-12345678"), [])

    def test_regular_ids_still_match(self):
        self.assertEqual(S.find_cves("CVE-2026-1234567, CVE 2026-114583; CVE-2024-4741."),
                         ["CVE-2026-1234567", "CVE-2026-114583", "CVE-2024-4741"])


if __name__ == "__main__":
    unittest.main()
