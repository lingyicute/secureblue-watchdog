"""RFC 3339 timestamps with non-UTC offsets order by instant, not string text."""
import unittest

from test_sbwatch import S


class TestTimestampOffsets(unittest.TestCase):
    def test_orient_compares_offset_timestamp_against_utc_by_instant(self):
        older = {"ref": "old", "created": "2026-11-16T08:00:00+02:00"}
        newer = {"ref": "new", "created": "2026-11-16T07:00:00Z"}
        a, b, swapped = S.orient(older, newer)
        self.assertFalse(swapped)
        self.assertEqual((a["ref"], b["ref"]), ("old", "new"))
        a2, b2, swapped2 = S.orient(newer, older)
        self.assertTrue(swapped2)
        self.assertEqual((a2["ref"], b2["ref"]), ("old", "new"))


    def test_nanosecond_and_compact_offset_timestamps_order_cleanly(self):
        earlier = "2026-11-17T03:06:51.981777100+0200"
        later = "2026-11-17T01:06:51.981777207Z"
        self.assertLess(S._ts_order(earlier), S._ts_order(later))


if __name__ == "__main__":
    unittest.main()
