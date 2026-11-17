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

    def test_hardlink_entry_resolves_its_archive_root_target(self):
        real = tarfile.TarInfo("usr/lib/sysimage/rpm/packages.db")
        lnk = tarfile.TarInfo("usr/share/rpm/rpmdb.sqlite")
        lnk.type = tarfile.LNKTYPE
        lnk.linkname = "usr/lib/sysimage/rpm/packages.db"
        raw = _make_tar([(real, b"hardlinked-rpmdb"), (lnk, None)])
        self.assertEqual(_extract(raw), b"hardlinked-rpmdb")


    def test_later_symlink_to_empty_stub_does_not_hide_earlier_real_target(self):
        real = tarfile.TarInfo("usr/lib/sysimage/rpm/real.db")
        stub = tarfile.TarInfo("usr/share/rpm/empty.db")
        s1 = tarfile.TarInfo("var/lib/rpm/rpmdb.sqlite")
        s1.type = tarfile.SYMTYPE
        s1.linkname = "../../../usr/lib/sysimage/rpm/real.db"
        s2 = tarfile.TarInfo("usr/share/rpm/rpmdb.sqlite")
        s2.type = tarfile.SYMTYPE
        s2.linkname = "empty.db"
        raw = _make_tar([(real, b"real-sqlite-bytes"), (stub, b""), (s1, None), (s2, None)])
        self.assertEqual(_extract(raw), b"real-sqlite-bytes")

    def test_chained_symlinks_and_dot_prefixed_directories_resolve(self):
        real = tarfile.TarInfo("./.rpm/real.db")
        mid = tarfile.TarInfo("usr/lib/sysimage/rpm/current")
        mid.type = tarfile.SYMTYPE
        mid.linkname = "../../../../.rpm/real.db"
        top = tarfile.TarInfo("usr/share/rpm/rpmdb.sqlite")
        top.type = tarfile.SYMTYPE
        top.linkname = "../../lib/sysimage/rpm/current"
        raw = _make_tar([(real, b"dot-chained-db"), (mid, None), (top, None)])
        self.assertEqual(_extract(raw), b"dot-chained-db")


if __name__ == "__main__":
    unittest.main()
