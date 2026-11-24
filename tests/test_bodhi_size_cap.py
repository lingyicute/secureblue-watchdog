"""Bodhi page fetches enforce MAX_JSON_BYTES instead of reading unbounded JSON."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestBodhiSizeCap(unittest.TestCase):
    def test_oversized_bodhi_reply_fails_cleanly_at_cap(self):
        class _Huge:
            headers = {}

            def read(self, n=-1):
                return b"{" + b" " * n

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        bodhi = S.Bodhi(cache_dir=None, max_calls=2, sleep=0)
        with patch.object(S, "MAX_JSON_BYTES", 64), \
                patch.object(S._OPENER, "open", return_value=_Huge()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bodhi.updates_for_src("kernel", "F45"), [])
        self.assertEqual(bodhi.failed, 1)


if __name__ == "__main__":
    unittest.main()

    def test_content_length_handles_whitespace_and_non_ascii_digits(self):
        self.assertEqual(S._content_length({"Content-Length": " 42 "}), 42)
        self.assertIsNone(S._content_length({"Content-Length": "\u00b2"}))
        self.assertIsNone(S._content_length({"Content-Length": "\u0661\u0660"}))
        self.assertIsNone(S._content_length({"Content-Length": "-1"}))
