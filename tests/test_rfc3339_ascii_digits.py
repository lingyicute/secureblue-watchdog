"""RFC 3339 timestamps accept only ASCII digits."""
import unittest

import sbwatch as S


class TestRfc3339AsciiDigits(unittest.TestCase):
    def test_non_ascii_fractional_digits_are_rejected(self):
        self.assertEqual(S._utc_timestamp("2026-11-24T22:32:31.١٢٣Z"), "")
        self.assertEqual(S._utc_timestamp("2026-11-24T22:32:31.123Z"),
                         "2026-11-24T22:32:31.123000000Z")


if __name__ == "__main__":
    unittest.main()
