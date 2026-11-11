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
        with patch.object(S.urllib.request, "urlopen", side_effect=fake_urlopen), \
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


if __name__ == "__main__":
    unittest.main()
