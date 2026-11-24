"""The tag list is read to its end: ghcr lists oldest first, so a cap hides new builds."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from test_sbwatch import S


class _Page(io.BytesIO):
    headers: dict = {}


class _Pages:
    """A registry with `count` tag pages, one tag on each."""

    def __init__(self, count):
        self.count, self.served = count, 0

    def open(self, req, timeout=None):
        self.served += 1
        page = _Page(json.dumps({"tags": [f"build{self.served}"]}).encode())
        if self.served < self.count:
            page.headers = {"Link": f'</v2/x/y/tags/list?n=1000&last=build{self.served}>; '
                                    f'rel="next"'}
        return page


class TestTagListPageBudget(unittest.TestCase):
    def _list(self, count):
        reg = S.Registry("ghcr.io/x/y")
        reg._token = lambda: None
        saved, S._OPENER = S._OPENER, _Pages(count)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                return S.list_tags(reg), err.getvalue()
        finally:
            S._OPENER = saved

    def test_a_repo_past_twelve_pages_still_shows_its_newest_tag(self):
        tags, log = self._list(13)
        self.assertEqual(len(tags), 13)
        self.assertEqual(tags[-1], "build13")
        self.assertNotIn("capped", log)

    def test_incomplete_tag_discovery_is_included_in_history_report_warnings(self):
        reg = S.Registry("ghcr.io/x/y")
        reg._token = lambda: None
        digest = "sha256:" + "a" * 64
        cur = {"index_digest": digest, "digest": digest, "annotations": {},
               "layers": [], "created": "2026-11-23T19:00:41Z"}
        with patch.object(S, "_OPENER", _Pages(2)), contextlib.redirect_stderr(io.StringIO()):
            tags = S.list_tags(reg, max_pages=1)
        self.assertEqual(tags, ["build1"])
        warnings = []
        with patch.object(S, "list_tags", return_value=tags):
            self.assertEqual(len(S.build_history(reg, cur=cur, warn=warnings)), 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("newest tags may be missing", warnings[0])

    def test_the_default_budget_leaves_years_of_headroom(self):
        self.assertGreaterEqual(S.TAG_LIST_MAX_PAGES, 50)


if __name__ == "__main__":
    unittest.main()
