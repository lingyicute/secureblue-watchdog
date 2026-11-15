"""A layer is read as a plain tar: no second decompression behind the caps."""
import io
import tarfile
import unittest
from unittest.mock import patch

from test_sbwatch import S

DATA = b"x" * 64


def _writes(mode):
    def fetch_blob(self, digest, dest):
        with tarfile.open(dest, mode) as tf:
            info = tarfile.TarInfo("usr/share/rpm/rpmdb.sqlite")
            info.size = len(DATA)
            tf.addfile(info, io.BytesIO(DATA))
        return dest
    return fetch_blob


class TestLayerPlainTar(unittest.TestCase):
    def _extract(self, mode):
        reg = S.Registry("x/y")
        try:
            with patch.object(S.Registry, "fetch_blob", _writes(mode)):
                path = reg.extract_member({"digest": "sha256:" + "0" * 64}, "rpmdb.sqlite")
            with open(path, "rb") as fh:
                return fh.read()
        finally:
            reg.close()

    def test_a_plain_tar_is_read(self):
        self.assertEqual(self._extract("w"), DATA)

    def test_a_compressed_tar_inside_the_layer_is_refused(self):
        with self.assertRaises(SystemExit) as ctx:
            self._extract("w:gz")
        self.assertIn("not a readable tar", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
