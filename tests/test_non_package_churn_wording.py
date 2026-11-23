"""The skip headline names what the non-package chunks of a chunkah image hold."""
import unittest

from test_sbwatch import S, pkg


class TestNonPackageChurnWording(unittest.TestCase):
    def test_the_chunks_are_named_for_what_they_are(self):
        # Three of the non-package chunks that moved between the live 45.20261119.0
        # and 45.20261123.0: no layer of such an image carries "ostree metadata".
        chunks = [{"components": [c], "size": size, "stability": 0.0} for c, size in (
            ("bigfiles/initramfs.img", 247044628), ("bigfiles/rpmdb.sqlite", 33688806),
            ("chunkah/unclaimed", 9970218))]
        changed = [{"name": "os-prober", "old": pkg("os-prober", "1.81-12.fc45"),
                    "new": pkg("os-prober", "1.81-13.fc45"), "src": "os-prober",
                    "dir": "upgrade", "cls": {}}]
        diff = {"changed": changed, "added": [], "removed": [], "count_a": 3, "count_b": 3}
        ldiff = {"download_bytes": sum(c["size"] for c in chunks), "changed_chunks": chunks}
        v = S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff))
        self.assertEqual(v["level"], "skip")
        self.assertIn("277.2 MiB of the download is non-package churn "
                      "(initramfs, rpmdb and other files no package owns)", v["headline"])
        self.assertNotIn("ostree metadata", v["headline"])
        self.assertIn("（initramfs、rpmdb 及其他不属于软件包的文件）", v["headline_zh"])
        self.assertNotIn("ostree 元数据", v["headline_zh"])


if __name__ == "__main__":
    unittest.main()
