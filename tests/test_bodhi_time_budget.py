"""Elapsed query budget is shared by pages, sources, and retries."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sbwatch as S


class TestBodhiTimeBudget(unittest.TestCase):
    def test_partial_page_is_not_cached_and_next_source_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(S.time, "monotonic", return_value=10) as clock:
            client = S.Bodhi(cache_dir=tmp, max_seconds=4, sleep=0)

            def page(*args):
                clock.return_value = 14
                return {"pages": 2, "total": 2}, [{"alias": "FEDORA-a", "type": "security"}]

            with patch.object(client, "_fetch_page", side_effect=page) as fetch:
                self.assertEqual(len(client.updates_for_src("curl", "F45")), 1)
                self.assertEqual(client.updates_for_src("glibc", "F45"), [])
                self.assertEqual(len(client.updates_for_src("curl", "F45")), 1)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(client.truncated_src, {"curl"})
            self.assertEqual(client.skipped, 1)
            self.assertTrue(client.time_limited)
            self.assertFalse(list(Path(tmp).glob("*.json")))

    def test_request_timeout_is_bounded_by_remaining_time(self):
        with patch.object(S.time, "monotonic", return_value=5) as clock:
            client = S.Bodhi(max_seconds=10, sleep=0)
            clock.return_value = 13

            def timeout(url, *, timeout):
                self.assertEqual(timeout, 2)
                clock.return_value = 15
                raise TimeoutError

            with patch.object(S._OPENER, "open", side_effect=timeout) as request:
                self.assertEqual(client.updates_for_src("curl", "F45"), [])
            self.assertEqual(request.call_count, 1)
            self.assertEqual(client.failed, 1)

    def test_verdict_reports_elapsed_budget(self):
        diff = {"changed": [], "added": [], "removed": [], "count_a": 1, "count_b": 1}
        verdict = S.verdict_of(diff, {"download_bytes": 1, "changed_chunks": []}, {},
                               bodhi_state={"skipped": 1, "time_limited": True})
        self.assertIn("--bodhi-seconds", verdict["headline"])
