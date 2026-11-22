"""The token realm is the registry's word: only an http(s) one may be opened."""
import contextlib
import email.message
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S


def challenge(realm):
    hdrs = email.message.Message()
    hdrs["Www-Authenticate"] = f'Bearer realm="{realm}",service="registry.example"'
    return S.urllib.error.HTTPError("https://registry.example/v2/", 401, "Unauthorized",
                                    hdrs, None)


class TestTokenRealm(unittest.TestCase):
    def _token(self, realm, replies=()):
        opened, replies = [], list(replies)

        def fake_urlopen(req, timeout=None):
            opened.append(req if isinstance(req, str) else req.full_url)
            if len(opened) == 1:
                raise challenge(realm)
            return replies.pop(0)

        reg = S.Registry("registry.example/ns/image")
        err = io.StringIO()
        with patch.object(S._OPENER, "open", side_effect=fake_urlopen), \
                contextlib.redirect_stderr(err):
            tok = reg._token()
        return tok, opened, err.getvalue()

    def test_a_realm_that_is_not_http_is_never_opened(self):
        # urlopen() would read a local file or reach into an internal FTP server
        for realm in ("file:///etc/passwd", "ftp://internal.example/token",
                      "data:application/json,{}"):
            with self.subTest(realm=realm):
                tok, opened, err = self._token(realm)
                self.assertIsNone(tok)
                self.assertEqual(opened, ["https://registry.example/v2/"])
                self.assertIn("not http(s)", err)

    def test_an_https_realm_still_yields_the_token(self):
        tok, opened, _ = self._token("https://auth.example/token",
                                     [io.BytesIO(b'{"token": "abc"}')])
        self.assertEqual(tok, "abc")
        self.assertEqual(len(opened), 2)
        self.assertTrue(opened[1].startswith("https://auth.example/token?"), opened[1])

    def test_realm_with_existing_query_uses_ampersand_and_rejects_bad_token_types(self):
        import contextlib, io, urllib.error
        from unittest.mock import patch
        seen = []

        def fake_urlopen(req, timeout=90):
            url = req.full_url if hasattr(req, "full_url") else req
            seen.append(url)
            if url.endswith("/v2/"):
                raise urllib.error.HTTPError(
                    url, 401, "Unauthorized",
                    {"Www-Authenticate": 'Bearer realm="https://auth.example/tok?v=1",service="reg"'},
                    io.BytesIO(b""))
            class _R:
                def read(self, n=-1):
                    return b'{"token": 12345}'
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False
            return _R()

        reg = S.Registry("reg.example/ns/img")
        with patch.object(S._OPENER, "open", side_effect=fake_urlopen),                 contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(reg._token())
        self.assertEqual(seen[1].count("?"), 1)
        self.assertIn("?v=1&service=reg", seen[1])


    def test_case_insensitive_and_multi_challenge_bearer_headers_parse(self):
        for hdr in (
            'bearer REALM="https://auth.example/token",SERVICE="reg.example"',
            'Basic realm="other", Bearer realm="https://auth.example/token",service="reg.example"',
            'Bearer realm="https://auth.example/token",service="reg.example", Basic realm="ignored"',
        ):
            with self.subTest(hdr=hdr):
                seen = []
                def fake_urlopen(req, timeout=None):
                    u = req.full_url if hasattr(req, "full_url") else req
                    seen.append(u)
                    if len(seen) == 1:
                        msg = email.message.Message()
                        msg["Www-Authenticate"] = hdr
                        raise S.urllib.error.HTTPError(u, 401, "Unauthorized", msg, None)
                    return io.BytesIO(b'{"token": "ok"}')
                reg = S.Registry("reg.example/ns/img")
                with patch.object(S._OPENER, "open", side_effect=fake_urlopen):
                    self.assertEqual(reg._token(), "ok")
                self.assertIn("https://auth.example/token?", seen[1])
                self.assertIn("service=reg.example", seen[1])


    def test_realm_fragment_does_not_swallow_query_parameters(self):
        tok, opened, _ = self._token("https://auth.example/token#frag",
                                     [io.BytesIO(b'{"token": "xyz"}')])
        self.assertEqual(tok, "xyz")
        self.assertNotIn("#", opened[1])
        self.assertIn("?service=registry.example&scope=", opened[1])

    def test_token_requests_do_not_bypass_safe_opener(self):
        with patch.object(S.urllib.request, "urlopen", side_effect=AssertionError("unsafe opener")), \
                patch.object(S._OPENER, "open", side_effect=[
                    challenge("https://auth.example/token"),
                    io.BytesIO(b'{"token": "safe"}'),
                ]):
            self.assertEqual(S.Registry("registry.example/ns/image")._token(), "safe")


if __name__ == "__main__":
    unittest.main()
