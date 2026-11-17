"""Image reference parsing rejects empty digests and handles mixed-case hosts."""
import unittest

from test_sbwatch import S


class TestImageRefParsing(unittest.TestCase):
    def test_trailing_at_is_rejected_instead_of_silently_using_latest(self):
        for bad in ("ns/name@", "ghcr.io/ns/name@", "ghcr.io/ns/name:latest@"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                S.Registry._split(bad)

    def test_tag_pagination_accepts_same_host_in_lowercase_when_ref_used_uppercase(self):
        import io
        from unittest.mock import patch

        class _Resp(io.BytesIO):
            def __init__(self, body, link=None):
                super().__init__(body)
                self.headers = {"Link": link} if link else {}

        pages = [_Resp(b'{"tags": ["a"]}',
                       '<https://ghcr.io/v2/ns/name/tags/list?last=a>; rel="next"'),
                 _Resp(b'{"tags": ["b"]}')]
        reg = S.Registry("GHCR.IO/ns/name")
        with patch.object(reg, "_token", return_value="tok"),                 patch.object(S._OPENER, "open", side_effect=pages):
            self.assertEqual(S.list_tags(reg), ["a", "b"])


    def test_empty_repository_segment_is_rejected(self):
        for bad in ("secureblue//silverblue-main-hardened",
                    "ghcr.io/secureblue//silverblue-main-hardened:latest"):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    S.Registry._split(bad)


    def test_manifest_ref_rejects_path_traversal_query_fragment_and_whitespace(self):
        reg = S.Registry("secureblue/silverblue-main-hardened")
        for bad in ("../other/manifests/latest", "latest?n=1", "latest#frag",
                    "latest%2f..", "latest\r\nX: 1", "a b", ".."):
            with self.subTest(bad=bad):
                with self.assertRaises(S.RegistryError):
                    reg.resolve(bad, light=True)
                with self.assertRaises(S.RegistryError):
                    reg.index_digest(bad)


if __name__ == "__main__":
    unittest.main()
