"""Relative tar symlinks and rpmdb extraction/parse cleanup regressions."""
import io
import os
import sqlite3
import tarfile
import tempfile
import types
import unittest

from test_sbwatch import S


class TestTarAndRpmdbCleanup(unittest.TestCase):
    def _tar_bytes(self, entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, kind, payload in entries:
                ti = tarfile.TarInfo(name)
                if kind == "sym":
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = payload
                    tf.addfile(ti)
                else:
                    ti.size = len(payload)
                    tf.addfile(ti, io.BytesIO(payload))
        return buf.getvalue()

    def test_pick_tar_member_resolves_relative_symlink_targets(self):
        raw = self._tar_bytes([
            ("usr/share/rpm/rpmdb.sqlite", "sym",
             "../../lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite"),
        ])
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            chosen, target = S.pick_tar_member(tf, "rpmdb.sqlite")
        self.assertIsNone(chosen)
        self.assertEqual(target, "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite")

    def test_extract_member_follows_relative_symlink_and_removes_blob(self):
        raw = self._tar_bytes([
            ("usr/share/rpm/rpmdb.sqlite", "sym",
             "../../lib/sysimage/rpm-ostree-base-db/target.db"),
            ("usr/lib/sysimage/rpm-ostree-base-db/target.db", "file", b"sqlite-bytes"),
        ])
        reg = S.Registry("secureblue/x")
        try:
            def fake_fetch(digest, dest):
                with open(dest, "wb") as fh:
                    fh.write(raw)
                return dest

            reg.fetch_blob = fake_fetch
            out = reg.extract_member({"digest": "sha256:" + "a" * 64}, "rpmdb.sqlite")
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"sqlite-bytes")
            self.assertEqual([n for n in os.listdir(reg._tmpdir()) if n.endswith(".blob")], [])
        finally:
            reg.close()

    def test_extract_member_cleans_up_blob_when_member_is_missing(self):
        raw = self._tar_bytes([("etc/os-release", "file", b"ID=fedora")])
        reg = S.Registry("secureblue/x")
        try:
            def fake_fetch(digest, dest):
                with open(dest, "wb") as fh:
                    fh.write(raw)
                return dest

            reg.fetch_blob = fake_fetch
            with self.assertRaises(SystemExit):
                reg.extract_member({"digest": "sha256:" + "b" * 64}, "rpmdb.sqlite")
            self.assertEqual(os.listdir(reg._tmpdir()), [])
        finally:
            reg.close()

    def test_package_list_handles_corrupt_sqlite_and_unlinks_extracted_file(self):
        with tempfile.TemporaryDirectory() as d:
            bad_db = os.path.join(d, "corrupt.sqlite")
            with open(bad_db, "wb") as fh:
                fh.write(b"not a valid sqlite3 file at all")
            reg = types.SimpleNamespace(extract_member=lambda chunk, match: bad_db)
            resolved = {"layers": [{"digest": "sha256:" + "c" * 64, "size": 10,
                                    "components": ["bigfiles/rpmdb.sqlite"]}]}
            with self.assertRaisesRegex(SystemExit, "unexpected rpmdb schema"):
                S.package_list(reg, resolved)
            self.assertFalse(os.path.exists(bad_db))

    def test_extract_member_follows_a_relative_target_without_a_leading_dot(self):
        # only a leading "/" makes a symlink target absolute
        raw = self._tar_bytes([
            ("usr/share/rpm/rpmdb.sqlite", "sym", "base-db/target.db"),
            ("usr/share/rpm/base-db/target.db", "file", b"sqlite-bytes"),
        ])
        reg = S.Registry("secureblue/x")
        try:
            def fake_fetch(digest, dest):
                with open(dest, "wb") as fh:
                    fh.write(raw)
                return dest

            reg.fetch_blob = fake_fetch
            out = reg.extract_member({"digest": "sha256:" + "d" * 64}, "rpmdb.sqlite")
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"sqlite-bytes")
        finally:
            reg.close()

    def test_absolute_symlink_target_is_normalised_from_the_archive_root(self):
        self.assertEqual(
            S._resolve_tar_link("usr/share/rpm/rpmdb.sqlite",
                                "/usr/lib/sysimage/../rpm/target.db"),
            "usr/lib/rpm/target.db")

    def _empty_db(self, directory):
        os.makedirs(directory)
        path = os.path.join(directory, "rpmdb.sqlite")
        con = sqlite3.connect(path)
        con.execute("create table Packages (hnum integer primary key, blob blob)")
        con.commit()
        con.close()
        return path

    def test_package_list_opens_a_database_under_a_directory_with_uri_characters(self):
        # TMPDIR is the user's: `#` starts a URI fragment, `?` a query and `%` an escape
        resolved = {"layers": [{"digest": "sha256:" + "e" * 64, "size": 10,
                                "components": ["bigfiles/rpmdb.sqlite"]}]}
        for odd in ("a#b", "c%41", "d?e", "f g"):
            with self.subTest(directory=odd), tempfile.TemporaryDirectory() as d:
                db = self._empty_db(os.path.join(d, odd))
                reg = types.SimpleNamespace(extract_member=lambda chunk, match, p=db: p)
                self.assertEqual(len(S.package_list(reg, resolved)), 0)
                self.assertFalse(os.path.exists(db))

    def test_the_sqlite_error_is_part_of_the_schema_failure(self):
        with tempfile.TemporaryDirectory() as d:
            bad_db = os.path.join(d, "corrupt.sqlite")
            with open(bad_db, "wb") as fh:
                fh.write(b"not a valid sqlite3 file at all")
            reg = types.SimpleNamespace(extract_member=lambda chunk, match: bad_db)
            resolved = {"layers": [{"digest": "sha256:" + "f" * 64, "size": 10,
                                    "components": ["bigfiles/rpmdb.sqlite"]}]}
            with self.assertRaisesRegex(SystemExit, "no Packages table.*not a database"):
                S.package_list(reg, resolved)
