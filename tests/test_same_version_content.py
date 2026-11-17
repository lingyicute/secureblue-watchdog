"""An unchanged RPM identity cannot prove that its installed files are unchanged."""
import unittest
from test_sbwatch import S


class TestSameVersionContent(unittest.TestCase):
    def inputs(self, component):
        diff = {"changed": [], "added": [], "removed": [], "count_a": 2223, "count_b": 2223}
        ld = {"download_bytes": 85450390, "total_size_b": 85450390,
              "chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
              "download_pct": 100, "changed_packages_from_chunks": [component[4:]],
              "changed_chunks": [{"components": [component], "size": 85450390}]}
        return diff, ld, S.crosscheck_chunks(ld, diff)

    def test_sensitive_same_version_chunk_requires_review(self):
        # glibc's chunk changed on the real 20261114 -> 20261116 images at the same EVR.
        diff, ld, xc = self.inputs("rpm/glibc")
        v = S.verdict_of(diff, ld, {}, xc)
        self.assertEqual(v["level"], "consider")
        self.assertIn("security-relevant packages were rebuilt", v["level_basis"])

    def test_equal_rpmdb_fast_path_does_not_hide_sensitive_content(self):
        diff, ld, xc = self.inputs("rpm/glibc")
        diff.update(count_a="?", count_b="?", same_rpmdb=True)
        self.assertEqual(S.verdict_of(diff, ld, {}, xc)["level"], "consider")

    def test_non_sensitive_same_version_is_not_a_content_identity_claim(self):
        diff, ld, xc = self.inputs("rpm/example")
        v = S.verdict_of(diff, ld, {}, xc)
        img = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}}
        md = S.render_markdown("test", img, img, diff, ld, v, [], xc)
        self.assertNotIn("no new package content", v["headline"])
        self.assertNotIn("no package content changed", md)
        self.assertNotIn("软件包层面没有新内容", md)
        self.assertIn("not inspected", md)


if __name__ == "__main__":
    unittest.main()
