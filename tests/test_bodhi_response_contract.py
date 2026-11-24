"""A JSON error response must never become a persistent clean answer."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, _FakeResp


class TestBodhiResponseContract(unittest.TestCase):
    def test_invalid_pages_are_failed_not_cached(self):
        cases = [{"error": "service unavailable"}, {"updates": None},
                 {"updates": [], "errors": [{"description": "unavailable"}]},
                 {"updates": [{}]}, {"updates": [{"date_stable": float("nan")}]},
                 {"updates": [{"content_type": 3}]},
                 {"updates": [{"builds": [{"nvr": None, "type": 3}]}]},
                 {"updates": [{"bugs": {"title": "not a list"}}]}]
        for doc in cases:
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as td:
                api = S.Bodhi(cache_dir=td, sleep=0, max_calls=1)
                with patch.object(S._OPENER, "open", return_value=_FakeResp(json.dumps(doc).encode())):
                    self.assertEqual(api.updates_for_src("dnf5", "F45"), [])
                self.assertEqual(api.failed, 1)
                self.assertFalse(list(Path(td).glob("*.json")))

    def test_valid_empty_response_is_cacheable(self):
        with tempfile.TemporaryDirectory() as td:
            api = S.Bodhi(cache_dir=td, sleep=0, max_calls=1)
            with patch.object(S._OPENER, "open", return_value=_FakeResp(b'{"updates": [], "total": 0}')):
                self.assertEqual(api.updates_for_src("dnf5", "F45"), [])
            self.assertEqual(api.failed, 0)
            self.assertTrue(list(Path(td).glob("*.json")))
