"""_CappedReader.peek accumulates short reads before inspecting magic bytes."""
import unittest

import sbwatch as S


class _ShortReader:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, size=-1):
        return self._chunks.pop(0) if self._chunks else b""


class TestCappedReaderPeek(unittest.TestCase):
    def test_peek_handles_one_byte_chunks_and_preserves_stream(self):
        reader = S._CappedReader(_ShortReader([b"\x1f", b"\x8b", b"rest"]), 100, "test")
        self.assertEqual(reader.peek(2), b"\x1f\x8b")
        self.assertEqual(reader.read(10), b"\x1f\x8brest")


if __name__ == "__main__":
    unittest.main()
