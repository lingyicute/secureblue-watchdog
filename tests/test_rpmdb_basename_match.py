"""SQLite sidecar files (-wal, -shm) must not match as rpmdb.sqlite."""
import io
import tarfile
import unittest

from test_sbwatch import S


class TestRpmdbBasenameMatch(unittest.TestCase):
    def test_rpmdb_chunk_ignores_smaller_sidecar_component(self):
        img = {"layers": [
            {"digest": "sha256:" + "1" * 64, "size": 33_000_000,
             "components": ["bigfiles/rpmdb.sqlite"]},
            {"digest": "sha256:" + "2" * 64, "size": 512,
             "components": ["bigfiles/rpmdb.sqlite-shm"]},
        ]}
        self.assertEqual(S.rpmdb_chunk(img)["digest"], "sha256:" + "1" * 64)

    def test_pick_tar_member_ignores_larger_wal_sidecar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:") as tf:
            for name, payload in (("usr/lib/sysimage/rpm/rpmdb.sqlite", b"db" * 20),
                                  ("usr/lib/sysimage/rpm/rpmdb.sqlite-wal", b"w" * 200)):
                ti = tarfile.TarInfo(name)
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:") as tf:
            chosen, target = S.pick_tar_member(tf, "rpmdb.sqlite")
        self.assertEqual(chosen.name, "usr/lib/sysimage/rpm/rpmdb.sqlite")
        self.assertIsNone(target)


if __name__ == "__main__":
    unittest.main()
