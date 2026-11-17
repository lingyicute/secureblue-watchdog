"""read_header must not read strings or integers past the declared data store."""
import struct
import unittest

from test_sbwatch import S


class TestRpmHeaderStoreBounds(unittest.TestCase):
    def test_unterminated_string_cannot_spill_into_trailer_bytes(self):
        store = b"foo"  # missing NUL inside hlen
        trailer = b"bar\0"
        idx = struct.pack(">IIII", 1000, 6, 0, 1)
        blob = struct.pack(">II", 1, len(store)) + idx + store + trailer
        stats = {}
        h = S.read_header(blob, stats)
        self.assertNotIn("name", h)
        self.assertEqual(stats["fields_skipped"], 1)

    def test_int32_tag_cannot_read_into_trailer_bytes(self):
        store = b"foo\0"
        trailer = struct.pack(">I", 7)
        idx = struct.pack(">IIII", 1000, 6, 0, 1) + struct.pack(">IIII", 1003, 4, 4, 1)
        blob = struct.pack(">II", 2, len(store)) + idx + store + trailer
        stats = {}
        h = S.read_header(blob, stats)
        self.assertEqual(h["name"], "foo")
        self.assertNotIn("epoch", h)
        self.assertEqual(stats["fields_skipped"], 1)


    def test_string_array_on_scalar_tag_is_skipped_instead_of_returning_list(self):
        import struct
        store = b"foo\x00bar\x001.0\x00"
        idx = struct.pack(">IIII", 1000, 8, 0, 2) + struct.pack(">IIII", 1001, 6, 8, 1)
        blob = struct.pack(">II", 2, len(store)) + idx + store
        stats = {}
        hdr = S.read_header(blob, stats)
        self.assertNotIn("name", hdr)
        self.assertEqual(hdr.get("version"), "1.0")
        self.assertEqual(stats.get("fields_skipped"), 1)

    def test_zero_count_changelog_text_returns_empty_list(self):
        import struct
        store = b"foo\x001.0\x00"
        idx = (struct.pack(">IIII", 1000, 6, 0, 1)
               + struct.pack(">IIII", 1001, 6, 4, 1)
               + struct.pack(">IIII", 1082, 8, 4, 0))
        blob = struct.pack(">II", 3, len(store)) + idx + store
        hdr = S.read_header(blob)
        self.assertEqual(hdr["changelogtext"], [])


if __name__ == "__main__":
    unittest.main()
