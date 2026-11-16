"""An expired bearer token is refreshed once on HTTP 401."""
import io
import unittest
import urllib.error
from unittest.mock import patch

from test_sbwatch import S


class TestTokenRefresh(unittest.TestCase):
    def test_expired_cached_token_is_refreshed_and_request_succeeds(self):
        reg = S.Registry("ghcr.io/x/y")
        reg._tok = "expired-tok"
        seen_auth = []

        def fake_token():
            if reg._tok is None:
                reg._tok = "fresh-tok"
            return reg._tok

        class _Ok(io.BytesIO):
            headers = {}

        def fake_open(req, timeout=90):
            auth = req.get_header("Authorization")
            seen_auth.append(auth)
            if auth == "Bearer expired-tok":
                raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b""))
            return _Ok(b"ok")

        with patch.object(reg, "_token", side_effect=fake_token), \
                patch.object(S._OPENER, "open", side_effect=fake_open):
            self.assertEqual(reg.get("manifests/latest", "application/json"), b"ok")
        self.assertEqual(seen_auth, ["Bearer expired-tok", "Bearer fresh-tok"])

    def test_repeated_401_still_raises_registry_error(self):
        reg = S.Registry("ghcr.io/x/y")
        reg._tok = "tok1"
        calls = []

        def fake_open(req, timeout=90):
            calls.append(1)
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b""))

        with patch.object(reg, "_token",
                          side_effect=lambda: setattr(reg, "_tok", "tok2") or "tok2"), \
                patch.object(S._OPENER, "open", side_effect=fake_open):
            with self.assertRaises(S.RegistryError) as ctx:
                reg.get("manifests/latest", "application/json")
        self.assertEqual(ctx.exception.http_code, 401)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
