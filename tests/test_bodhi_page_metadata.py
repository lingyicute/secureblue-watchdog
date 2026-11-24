"""Pagination follows the returned collection, before filtering out non-RPMs."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, _FakeResp


class TestBodhiPageMetadata(unittest.TestCase):
    def ask(self, documents, directory=None):
        client = S.Bodhi(cache_dir=directory, sleep=0, max_calls=len(documents))
        responses = [_FakeResp(json.dumps(d).encode()) for d in documents]
        with patch.object(S._OPENER, "open", side_effect=responses):
            result = client.updates_for_src("dnf5", "F45")
        return client, result

    def test_server_page_size_can_be_smaller_than_requested(self):
        pages = [{"page": 1, "pages": 2, "total": 2,
                  "updates": [{"content_type": "flatpak"}]},
                 {"page": 2, "pages": 2, "total": 2,
                  "updates": [{"alias": "FEDORA-2026-b9a53ff63c", "type": "security"}]}]
        client, rows = self.ask(pages)
        self.assertEqual([r["alias"] for r in rows], ["FEDORA-2026-b9a53ff63c"])
        self.assertEqual(client.truncated_src, set())
        self.assertEqual(client.calls, 2)

    def test_missing_final_rows_do_not_become_a_complete_cache(self):
        with tempfile.TemporaryDirectory() as td:
            client, _ = self.ask([{"total": 20, "pages": 1, "updates": []}], td)
            self.assertEqual(client.truncated_src, {"dnf5"})
            self.assertFalse(list(Path(td).glob("*.json")))

    def test_repeated_page_is_not_a_second_page(self):
        doc = {"total": 2, "pages": 2, "page": 1, "updates": [{"alias": "one"}]}
        client, rows = self.ask([doc, doc])
        self.assertEqual(len(rows), 1)
        self.assertEqual(client.failed, 1)
        self.assertEqual(client.truncated_src, {"dnf5"})

    def test_repeated_advisory_with_correct_page_number_is_incomplete(self):
        first = {"total": 2, "pages": 2, "page": 1, "updates": [{"alias": "one"}]}
        with tempfile.TemporaryDirectory() as td:
            client, rows = self.ask([first, dict(first, page=2)], td)
            self.assertEqual([r["alias"] for r in rows], ["one"])
            self.assertEqual(client.truncated_src, {"dnf5"})
            self.assertFalse(list(Path(td).glob("*.json")))
