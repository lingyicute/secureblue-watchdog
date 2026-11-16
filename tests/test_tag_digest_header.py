"""Tag probes normalise sha256 headers and hash the body on malformed ones."""
import hashlib
import io
import unittest

from test_sbwatch import S


class _Resp:
    def __init__(self, headers, body=b""):
        self.headers = headers
        self._buf = io.BytesIO(body)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _reg(headers, body=b""):
    reg = S.Registry.__new__(S.Registry)
    reg._open = lambda path, accept: _Resp(headers, body)
    return reg


class TestTagDigestHeader(unittest.TestCase):
    def test_uppercase_header_is_normalised_to_lowercase_sha256(self):
        want = "sha256:" + "ab" * 32
        reg = _reg({"Docker-Content-Digest": "  SHA256:" + "AB" * 32 + " "})
        self.assertEqual(reg.index_digest("20261116"), want)
        self.assertEqual(S.tag_exists(reg, "20261116"), want)

    def test_malformed_header_falls_back_to_hashing_the_manifest_body(self):
        body = b'{"manifests": []}'
        want = "sha256:" + hashlib.sha256(body).hexdigest()
        reg = _reg({"Docker-Content-Digest": "not-a-digest"}, body)
        self.assertEqual(reg.index_digest("20261116"), want)
        self.assertEqual(S.tag_exists(reg, "20261116"), want)


if __name__ == "__main__":
    unittest.main()
