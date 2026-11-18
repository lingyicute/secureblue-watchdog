"""`history` prints each row's whole digest: the table's clipped one is not a usable ref."""
import unittest

from test_history_snapshot_label import OTHER, SNAP, _run


class TestHistoryFullDigests(unittest.TestCase):
    def test_every_row_digest_is_printed_whole(self):
        out, _ = _run(return_value=OTHER)
        self.assertIn(f"    2026-11-17T01:06:51  {SNAP}\n", out)


if __name__ == "__main__":
    unittest.main()
