"""Manifest-only reports do not claim to have fetched rpmdb.sqlite."""
import unittest

from test_sbwatch import S


class TestManifestOnlyFooter(unittest.TestCase):
    def test_footer_reflects_manifest_only_mode(self):
        diff = {"changed": [], "added": [], "removed": [], "count_a": "?", "count_b": "?"}
        ld = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
              "total_size_b": 1, "download_bytes": 0, "download_pct": 0,
              "changed_packages_from_chunks": [], "changed_chunks": []}
        v = S.degrade_manifest_only_verdict(S.verdict_of(diff, ld, {}), ld)
        img = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        md = S.render_markdown("s", img, img, diff, ld, v, [], {"versions_known": False})
        self.assertIn("registry manifests only", md)
        self.assertIn("未拉取 `rpmdb.sqlite`", md)
        self.assertNotIn("registry manifests + the image's `rpmdb.sqlite`", md)


if __name__ == "__main__":
    unittest.main()
