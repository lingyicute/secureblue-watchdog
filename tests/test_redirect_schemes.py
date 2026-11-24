import unittest.mock
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


    def test_bodhi_uses_scheme_checking_opener(self):
        client = S.Bodhi(cache_dir=None, sleep=0)
        with unittest.mock.patch.object(S.urllib.request, "urlopen",
                                        side_effect=AssertionError("unsafe opener")), \
                unittest.mock.patch.object(S._OPENER, "open",
                                           side_effect=urllib.error.HTTPError(
                                               "https://bodhi.fedoraproject.org/updates/",
                                               302, "refused redirect to ftp: URL", {}, None)):
            self.assertEqual(client.updates_for_src("curl", "F45"), [])
        self.assertEqual(client.failed, 1)


if __name__ == "__main__":
    unittest.main()
