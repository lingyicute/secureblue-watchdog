"""Negative --days must probe zero dated tags rather than slicing [-days:] = [N:]."""
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestNegativeDays(unittest.TestCase):
    def test_build_history_with_negative_days_does_not_probe_dated_tags(self):
        cur = {"digest": "sha256:" + "1" * 64, "index_digest": "sha256:" + "1" * 64,
               "is_index": True, "created": "2026-11-16T00:00:00Z", "annotations": {},
               "layers": []}

        class _Reg:
            def index_digest(self, ref):
                raise AssertionError(f"should not probe {ref}")

        with patch.object(S, "list_tags", return_value=["20261115", "20261116"]):
            rows = S.build_history(_Reg(), scan=1, days=-3, to="latest", cur=cur)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
