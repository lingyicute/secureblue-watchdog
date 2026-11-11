"""Offline checks for registry credential and pagination boundaries."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from test_sbwatch import S


def response(doc, link=None):
    body = io.BytesIO(json.dumps(doc).encode())
    body.headers = {"Link": f'<{link}>; rel="next"'} if link else {}
    return body


class TestRegistryBoundaries(unittest.TestCase):
    def setUp(self):
        self.reg = S.Registry("registry.example/ns/image")
        self.reg._tok = "test-pull-token"

    def test_https_downgrade_does_not_forward_authorization(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                request = S.urllib.request.Request(
                    "https://registry.example/v2/ns/image/blobs/digest",
                    headers={"Authorization": "Bearer secret", "Accept": "application/json"})
                redirected = S._SameHostAuthRedirect().redirect_request(
                    request, None, status, "redirect", {},
                    "http://registry.example/v2/ns/image/blobs/digest")
                self.assertIsNone(redirected.get_header("Authorization"))
                self.assertEqual(redirected.get_header("Accept"), "application/json")

    def test_tag_requests_use_the_hardened_opener(self):
        with patch.object(S._OPENER, "open", return_value=response({"tags": ["latest"]})) as safe, \
                patch.object(S.urllib.request, "urlopen", side_effect=AssertionError("unsafe opener")), \
                patch.object(S.time, "sleep"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(S.list_tags(self.reg), ["latest"])
        self.assertEqual(safe.call_count, 1)
        self.assertEqual(safe.call_args.args[0].get_header("Authorization"),
                         "Bearer test-pull-token")

    def _walk(self, docs, links=()):
        requests = []

        def open_page(req, timeout=None):
            i = len(requests)
            requests.append(req)
            return response(docs[min(i, len(docs) - 1)], links[i] if i < len(links) else None)

        with patch.object(S._OPENER, "open", side_effect=open_page), \
                patch.object(S.urllib.request, "urlopen", side_effect=open_page), \
                patch.object(S.time, "sleep"), contextlib.redirect_stderr(io.StringIO()) as err:
            tags = S.list_tags(self.reg, max_pages=3)
        return tags, requests, err.getvalue()

    def test_relative_pagination_links_are_resolved_against_the_current_page(self):
        for link in ("?n=1000&last=a", "list?n=1000&last=a",
                     "/v2/ns/image/tags/list?n=1000&last=a",
                     "https://registry.example/v2/ns/image/tags/list?n=1000&last=a"):
            with self.subTest(link=link):
                tags, requests, _ = self._walk([{"tags": ["a"]}, {"tags": ["b"]}], [link])
                self.assertEqual(tags, ["a", "b"])
                self.assertEqual(requests[1].full_url,
                                 "https://registry.example/v2/ns/image/tags/list?n=1000&last=a")

    def test_unsafe_next_links_are_not_requested(self):
        for link in ("https://attacker.example/collect", "//attacker.example/collect",
                     "http://registry.example/collect", "file:///app/private",
                     "https://user@registry.example/collect", "https://[invalid"):
            with self.subTest(link=link):
                tags, requests, warning = self._walk([{"tags": ["a"]}], [link])
                self.assertEqual(tags, ["a"])
                self.assertEqual(len(requests), 1, "pagination escaped the registry origin")
                self.assertIn("history may be incomplete", warning)

    def test_invalid_page_shapes_are_retried_and_never_used(self):
        for doc in ([], ["tag"], "oops", 42, {}, {"tags": "latest"}, {"tags": [None]}):
            with self.subTest(doc=doc):
                tags, requests, warning = self._walk([doc])
                self.assertEqual(tags, [])
                self.assertEqual(len(requests), S.TAG_LIST_RETRIES)
                self.assertIn("history may be incomplete", warning)

    def test_valid_page_after_bad_shape_is_used(self):
        tags, requests, _ = self._walk([["not a document"], {"tags": ["ok"]}])
        self.assertEqual(tags, ["ok"])
        self.assertEqual(len(requests), 2)

    def test_null_tag_list_is_a_valid_empty_repository(self):
        tags, requests, warning = self._walk([{"tags": None}])
        self.assertEqual(tags, [])
        self.assertEqual(len(requests), 1)
        self.assertEqual(warning, "")


if __name__ == "__main__":
    unittest.main()
