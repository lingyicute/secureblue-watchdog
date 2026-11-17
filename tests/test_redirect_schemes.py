"""Registry redirects may only target http(s) URLs, never file: or ftp:."""
import unittest
import urllib.error
import urllib.request

from test_sbwatch import S


class TestRedirectSchemes(unittest.TestCase):
    def test_non_http_redirect_schemes_are_refused(self):
        handler = S._SameHostAuthRedirect()
        req = urllib.request.Request("https://ghcr.io/v2/x/y/blobs/sha256:" + "a" * 64,
                                     headers={"Authorization": "Bearer secret"})
        for bad in ("file:///etc/passwd", "ftp://mirror.example/blob", "data:text/plain,x"):
            with self.subTest(bad=bad):
                with self.assertRaises(urllib.error.HTTPError):
                    handler.redirect_request(req, None, 302, "Found", {}, bad)


if __name__ == "__main__":
    unittest.main()
