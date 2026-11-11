"""A 401/403 from the registry says what it most likely means."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S


def http_error(code):
    return S.urllib.error.HTTPError("https://ghcr.io/v2/x/y/manifests/latest", code,
                                    "nope", {}, None)


class TestRegistryAuthHint(unittest.TestCase):
    def _error(self, code):
        reg = S.Registry("ghcr.io/secureblue/does-not-exist")
        reg._tok = ""                      # no token: the request goes out anonymous
        with patch.object(S._OPENER, "open", side_effect=http_error(code)), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(S.RegistryError) as caught:
            reg.get("manifests/latest", S.MANIFEST_ACCEPT)
        return caught.exception

    def test_a_missing_or_private_repository_is_named_as_the_likely_cause(self):
        # ghcr answers 401, not 404, for a repository that does not exist
        for code in (401, 403):
            with self.subTest(code=code):
                e = self._error(code)
                self.assertEqual(e.http_code, code)
                self.assertIn(f"registry error {code} for "
                              f"secureblue/does-not-exist/manifests/latest", str(e))
                self.assertIn("no such repository", str(e))
                self.assertIn("--image", str(e))

    def test_other_statuses_carry_no_such_hint(self):
        for code in (429, 500, 503):
            with self.subTest(code=code):
                self.assertNotIn("no such repository", str(self._error(code)))


if __name__ == "__main__":
    unittest.main()
