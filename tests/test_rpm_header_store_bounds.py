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


if __name__ == "__main__":
    unittest.main()
