"""Symlink and hardlink tar entries resolve to the real file even past placeholders."""
import io
import os
import tarfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


def _make_tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for info, data in members:
            if data is not None:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(info)
    return buf.getvalue()


def _extract(tar_bytes):
    reg = S.Registry("x/y")
    layer = {"digest": "sha256:" + "c" * 64, "size": len(tar_bytes)}

    def fake_fetch(digest, dest):
        with open(dest, "wb") as f:
            f.write(tar_bytes)
        return dest

    try:
        with patch.object(reg, "fetch_blob", side_effect=fake_fetch):
            path = reg.extract_member(layer, "rpmdb.sqlite")
            with open(path, "rb") as f:
                data = f.read()
            os.unlink(path)
            return data
    finally:
        reg.close()


class TestTarLinks(unittest.TestCase):
    def test_symlink_to_larger_target_beats_zero_byte_placeholder(self):
        placeholder = tarfile.TarInfo("usr/share/rpm/rpmdb.sqlite")
        sym = tarfile.TarInfo("var/lib/rpm/rpmdb.sqlite")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../../usr/lib/sysimage/rpm/packages.db"
        real = tarfile.TarInfo("usr/lib/sysimage/rpm/packages.db")
        raw = _make_tar([(placeholder, b""), (sym, None), (real, b"SQLite format 3\0real")])
        self.assertEqual(_extract(raw), b"SQLite format 3\0real")


if __name__ == "__main__":
    unittest.main()
