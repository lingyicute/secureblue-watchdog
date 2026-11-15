"""`no-change` speaks for the packages, not for the files no package owns."""
import unittest

from test_sbwatch import S

DIFF = {"changed": [], "added": [], "removed": [], "count_a": 3, "count_b": 3}


def _verdict(*components):
    chunks = [{"components": [c], "size": 4096, "stability": 0.0} for c in components]
    return S.verdict_of(DIFF, {"download_bytes": 4096 * len(chunks),
                               "changed_chunks": chunks}, {})


class TestNoChangeWording(unittest.TestCase):
    def test_changed_unowned_files_are_named_as_not_inspected(self):
        v = _verdict("bigfiles/initramfs.img", "chunkah/unclaimed")
        self.assertEqual(v["level"], "no-change")
        self.assertIn("Not inspected: 4.0 KiB of files that no package owns", v["headline"])
        self.assertIn("未检查：另有 4.0 KiB 不属于任何软件包的文件", v["headline_zh"])

    def test_nothing_is_added_when_that_chunk_did_not_move(self):
        v = _verdict("bigfiles/initramfs.img")
        self.assertEqual(v["level"], "no-change")
        self.assertNotIn("Not inspected", v["headline"])

    def test_the_badge_does_not_claim_a_rebuild(self):
        self.assertNotIn("REBUILD", S.ICON_EN["no-change"])
        self.assertNotIn("重建", S.ICON_ZH["no-change"])


if __name__ == "__main__":
    unittest.main()
