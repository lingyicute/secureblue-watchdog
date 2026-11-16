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

    def test_the_report_body_does_not_claim_all_rebuild_when_unclaimed_moved(self):
        chunks = [{"components": ["chunkah/unclaimed"], "size": 4096, "stability": 0.0}]
        ld = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
              "total_size_b": 4096, "download_bytes": 4096, "download_pct": 100,
              "changed_packages_from_chunks": [], "changed_chunks": chunks}
        img = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        md = S.render_markdown("s", img, img, DIFF, ld, S.verdict_of(DIFF, ld, {}), [])
        self.assertNotIn("entirely rebuilt content", md)
        self.assertNotIn("全部来自重建内容", md)
        self.assertIn("chunkah/unclaimed", md)


if __name__ == "__main__":
    unittest.main()
