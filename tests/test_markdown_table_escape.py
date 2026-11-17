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


if __name__ == "__main__":
    unittest.main()
