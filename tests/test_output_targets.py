"""Atomic output writers still work for a device, a pipe and a symlink as the target."""
import os
from pathlib import Path
import tempfile
import unittest

from test_sbwatch import S


class TestOutputTargets(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_a_named_pipe_is_written_to_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = os.path.join(d, "out.json")
            os.mkfifo(fifo)
            reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            try:
                S._atomic_write_json(fifo, {"a": 1})
                self.assertEqual(os.read(reader, 100), b'{"a": 1}')
            finally:
                os.close(reader)
            self.assertTrue(os.path.exists(fifo))
            self.assertFalse(Path(fifo).is_file())               # still the pipe
            self.assertEqual(os.listdir(d), ["out.json"])        # and no temp file

    @unittest.skipUnless(os.path.exists("/dev/null"), "needs /dev/null")
    def test_a_device_is_written_to_not_replaced(self):
        S._atomic_write_json("/dev/null", {"a": 1})
        S._atomic_write_text("/dev/null", "text")
        self.assertFalse(Path("/dev/null").is_file())
        self.assertTrue(Path("/dev/null").exists())

    def test_a_symlink_to_a_file_keeps_its_link(self):
        with tempfile.TemporaryDirectory() as d:
            real, link = Path(d, "real.json"), Path(d, "link.json")
            real.write_text("old")
            link.symlink_to(real)
            S._atomic_write_json(str(link), {"a": 1})
            S._atomic_write_text(str(Path(d, "real.json")), "x")
            S._atomic_write_json(str(link), {"b": 2})
            self.assertTrue(link.is_symlink())
            self.assertEqual(real.read_text(), '{"b": 2}')
            self.assertEqual(sorted(os.listdir(d)), ["link.json", "real.json"])


if __name__ == "__main__":
    unittest.main()
