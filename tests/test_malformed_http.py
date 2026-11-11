"""A reply that is not HTTP is a registry error, not a traceback."""
import contextlib
import http.client
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestMalformedHttpReply(unittest.TestCase):
    def test_open_reports_a_registry_error(self):
        reg = S.Registry("x/y")
        reg._tok = ""                       # no token round trip
        with patch.object(S._OPENER, "open",
                          side_effect=http.client.BadStatusLine("garbage")):
            with self.assertRaises(S.RegistryError) as caught:
                reg._open("manifests/latest", S.MANIFEST_ACCEPT)
        self.assertIsNone(caught.exception.http_code)
        self.assertIn("cannot reach ghcr.io", str(caught.exception))

    def test_token_probe_continues_unauthenticated(self):
        reg = S.Registry("x/y")
        with patch.object(S.urllib.request, "urlopen",
                          side_effect=http.client.LineTooLong("header line")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(reg._token())
        self.assertIn("cannot reach ghcr.io/v2/", err.getvalue())


if __name__ == "__main__":
    unittest.main()
