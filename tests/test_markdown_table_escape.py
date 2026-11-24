"""Pipes and newlines in image metadata or changelogs do not split markdown tables."""
import unittest

from test_sbwatch import S

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}


class TestMarkdownTableEscape(unittest.TestCase):
    def test_pipe_and_newline_in_version_and_kernel_annotations_are_escaped(self):
        a = {"ref": "a", "digest": "sha256:" + "1" * 64, "created": "2026-11-16T00:00:00Z",
             "annotations": {"org.opencontainers.image.version": "45|injected\nrow",
                             "ostree.linux": "7.3|bad"}}
        diff = {"added": [], "removed": [], "downgrades": [], "changed": [],
                "count_a": 1, "count_b": 1}
        v = S.verdict_of(diff, LD, {})
        md = S.render_markdown("s", a, a, diff, LD, v, [])
        found = False
        for ln in md.splitlines():
            if ln.startswith("| image version |"):
                found = True
                self.assertIn(r"45\|injected row", ln)
                self.assertEqual(ln.replace(r"\|", "").count("|"), 4)
        self.assertTrue(found)


    def test_backlog_and_routine_tables_escape_pipes_and_newlines(self):
        img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}
        ld = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
              "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
              "changed_packages_from_chunks": [], "changed_chunks": []}
        diff = {"added": [], "removed": [], "downgrades": [], "count_a": 1, "count_b": 1,
                "changed": [{"name": "a|b", "src": "src|1", "dir": "upgrade",
                             "old": {"evr": "1|0-1", "src": "src|1"},
                             "new": {"evr": "2\n0-1", "src": "src|1"}, "cls": {}}]}
        backlog = [{"name": "pkg|x", "have": "1-1", "want": "2-1",
                    "severity": "high|crit", "alias": "FEDORA-2026|bad\nline"}]
        v = S.verdict_of(diff, ld, {}, backlog=backlog)
        md = S.render_markdown("s", img, img, diff, ld, v, [], backlog=backlog)
        self.assertIn("src\\|1", md)
        self.assertIn("FEDORA-2026\\|bad line", md)



    def test_missing_inputhash_renders_placeholder_instead_of_empty_backticks(self):
        img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}
        diff = {"added": [], "removed": [], "downgrades": [], "changed": [],
                "count_a": 1, "count_b": 1}
        md = S.render_markdown("s", img, img, diff, LD, S.verdict_of(diff, LD, {}), [])
        self.assertIn("| rpm-ostree 输入哈希 | `—` | `—` |", md)
        self.assertIn("| rpm-ostree inputhash | `—` | `—` |", md)
        self.assertNotIn("``", md)


    def test_pipe_and_newline_in_inputhash_and_commit_cells_are_escaped(self):
        a = {"ref": "a", "digest": "sha256:" + "1" * 64, "created": "2026-11-16T00:00:00Z",
             "annotations": {"rpmostree.inputhash": "ab|cd\nef",
                             "ostree.commit": "12|34\n56"}}
        diff = {"added": [], "removed": [], "downgrades": [], "changed": [],
                "count_a": 1, "count_b": 1}
        md = S.render_markdown("s", a, a, diff, LD, S.verdict_of(diff, LD, {}), [])
        for prefix in ("| rpm-ostree inputhash |", "| ostree.commit |",
                       "| rpm-ostree 输入哈希 |", "| ostree 提交 |"):
            rows = [ln for ln in md.splitlines() if ln.startswith(prefix)]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].replace(r"\|", "").count("|"), 4)

if __name__ == "__main__":
    unittest.main()
