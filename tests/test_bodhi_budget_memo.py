"""Exhausted budgets are counted once per source/release, not per binary."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestBodhiBudgetMemo(unittest.TestCase):
    def test_many_subpackages_only_count_one_skipped_source(self):
        bodhi = S.Bodhi(max_calls=0)
        for _ in range(100):
            self.assertEqual(bodhi.updates_for_src("kernel", "F45"), [])
        self.assertEqual(bodhi.skipped, 1)
        self.assertEqual(bodhi.calls, 0)
        self.assertEqual(bodhi.failed, 0)

    def test_each_source_and_release_gets_its_own_budget_result(self):
        bodhi = S.Bodhi(max_calls=0)
        for source, release in (("kernel", "F45"), ("kernel", "F45"),
                                ("kernel", "F44"), ("openssl", "F45")):
            bodhi.updates_for_src(source, release)
        self.assertEqual(bodhi.skipped, 3)

    def test_budget_miss_is_only_memoized_in_this_run_not_written_to_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            first = S.Bodhi(cache_dir=directory, max_calls=0)
            path = Path(first._cf("kernel-F45"))
            path.write_text("[]")  # Obsolete cache that cannot establish coverage.
            with patch.object(first, "_read_cache_entry", wraps=first._read_cache_entry) as read:
                for _ in range(10):
                    first.updates_for_src("kernel", "F45")
            self.assertEqual(read.call_count, 1)
            self.assertEqual(path.read_text(), "[]")
            second = S.Bodhi(cache_dir=directory, max_calls=0)
            with patch.object(second, "_read_cache_entry", wraps=second._read_cache_entry) as read:
                second.updates_for_src("kernel", "F45")
            self.assertEqual(read.call_count, 1)
            self.assertEqual(second.skipped, 1)


if __name__ == "__main__":
    unittest.main()
