"""A one-call budget can finish a multi-page source without trusting a partial answer."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from test_sbwatch import S, _FakeResp


class TestBodhiPageResume(unittest.TestCase):
    def ask(self, cache, expected_page, aliases, *, total=3, now=1000):
        def respond(url, **kwargs):
            page = parse_qs(urlsplit(url).query)["page"]
            self.assertEqual(page, [str(expected_page)])
            return _FakeResp(json.dumps({"page": expected_page, "pages": 2, "total": total,
                                        "updates": [{"alias": alias, "builds": []} for alias in aliases]}).encode())

        client = S.Bodhi(cache_dir=cache, max_calls=1, sleep=0)
        with patch.object(S.time, "time", return_value=now), \
                patch.object(S.urllib.request, "urlopen", side_effect=respond):
            rows = client.updates_for_src("kernel", "F44")
        return client, [row["alias"] for row in rows]

    def test_budget_cut_resumes_at_the_next_page_and_keeps_first_page_ttl(self):
        with tempfile.TemporaryDirectory() as cache:
            client, rows = self.ask(cache, 1, ["a", "b"])
            self.assertEqual(client.truncated_src, {"kernel"})
            self.assertEqual(client.calls, 1)
            self.assertEqual(rows, ["a", "b"])
            self.assertEqual([p.name for p in Path(cache).glob("*.json")],
                             ["bodhi-kernel_F44.partial.json"])
            client, rows = self.ask(cache, 2, ["c"], now=1100)
            self.assertEqual(rows, ["a", "b", "c"])
            self.assertEqual(client.truncated_src, set())
            self.assertEqual(client.calls, 1)
            self.assertEqual([p.name for p in Path(cache).glob("*.json")],
                             ["bodhi-kernel_F44.json"])
            fresh = S.Bodhi(cache_dir=cache, max_calls=0)
            with patch.object(S.time, "time", return_value=1000 + S.BODHI_TTL - 1):
                self.assertEqual(len(fresh.updates_for_src("kernel", "F44")), 3)
            self.assertEqual(fresh.calls, 0)
            expired = S.Bodhi(cache_dir=cache, max_calls=0)
            with patch.object(S.time, "time", return_value=1000 + S.BODHI_TTL):
                self.assertEqual(expired.updates_for_src("kernel", "F44"), [])
            self.assertEqual(expired.skipped, 1)

    def test_shifted_collection_discards_partial_and_restarts(self):
        for total, rows in ((3, ["b"]), (4, ["c", "d"])):
            with self.subTest(total=total), tempfile.TemporaryDirectory() as cache:
                self.ask(cache, 1, ["a", "b"])
                client, result = self.ask(cache, 2, rows, total=total)
                self.assertEqual(result, [])
                self.assertEqual(client.truncated_src, {"kernel"})
                self.assertFalse(list(Path(cache).glob("*.json")))
                self.assertEqual(self.ask(cache, 1, ["a", "b"])[1], ["a", "b"])
