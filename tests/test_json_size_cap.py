"""Documents parsed in one piece are capped far below the 200 MiB blob cap."""
import contextlib
import email.message
import io
import json
import unittest
import urllib.error

from test_sbwatch import S


class _Resp(io.BytesIO):
    def __init__(self, body, declared=None):
        super().__init__(body)
        self.headers = {} if declared is None else {"Content-Length": str(declared)}


class _SmallCap(unittest.TestCase):
    """Runs with a 1 KiB cap, so no test has to build a 16 MiB body."""

    def setUp(self):
        self._saved_cap, S.MAX_JSON_BYTES = S.MAX_JSON_BYTES, 1024
        self._saved_urlopen = S.urllib.request.urlopen

    def tearDown(self):
        S.MAX_JSON_BYTES = self._saved_cap
        S.urllib.request.urlopen = self._saved_urlopen


class TestRegistryDocumentCap(_SmallCap):
    def test_the_cap_is_well_below_the_blob_cap(self):
        self.assertLess(self._saved_cap, S.MAX_BLOB_BYTES // 4)

    def test_a_document_within_the_cap_is_read_whole(self):
        reg = S.Registry("ghcr.io/x/y")
        self.assertEqual(reg._read_all(_Resp(b"x" * 1024), "manifest"), b"x" * 1024)

    def test_an_oversized_document_is_refused_by_its_declared_length(self):
        reg = S.Registry("ghcr.io/x/y")
        with self.assertRaises(SystemExit):
            reg._read_all(_Resp(b"", declared=1025), "manifest")

    def test_an_oversized_document_is_refused_while_reading(self):
        reg = S.Registry("ghcr.io/x/y")
        with self.assertRaises(SystemExit):
            reg._read_all(_Resp(b"x" * 1025), "manifest")


class TestTokenReplyCap(_SmallCap):
    def _token(self, body):
        def fake(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            if url.endswith("/v2/"):
                hdrs = email.message.Message()
                hdrs["Www-Authenticate"] = 'Bearer realm="https://auth.example/token"'
                raise urllib.error.HTTPError(url, 401, "Unauthorized", hdrs, io.BytesIO(b""))
            return io.BytesIO(body)

        S.urllib.request.urlopen = fake
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            return S.Registry("ghcr.io/x/y")._token(), err.getvalue()

    def test_a_normal_reply_still_yields_the_token(self):
        tok, _ = self._token(json.dumps({"token": "abc"}).encode())
        self.assertEqual(tok, "abc")

    def test_an_endless_reply_is_cut_off_and_tolerated(self):
        tok, log = self._token(json.dumps({"token": "abc", "pad": "x" * 2048}).encode())
        self.assertIsNone(tok)
        self.assertIn("token fetch failed", log)


if __name__ == "__main__":
    unittest.main()
