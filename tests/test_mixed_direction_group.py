"""An upgraded subpackage's CVE fix survives when a sibling subpackage downgrades."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
      "total_size_b": 100, "download_bytes": 100, "download_pct": 100,
      "changed_packages_from_chunks": ["kernel"], "changed_chunks": []}
IMG = {"ref": "a", "digest": "sha256:" + "0" * 64, "annotations": {}, "created": ""}


class TestMixedDirectionGroup(unittest.TestCase):
    def test_upgraded_sibling_cve_is_reported_alongside_downgrade(self):
        old_k = pkg("kernel", "7.3.3-300.secureblue.2.fc45", src="kernel")
        new_k = pkg("kernel", "7.3.3-300.secureblue.1.fc45", src="kernel")
        old_t = pkg("kernel-tools", "7.3.3-300.fc45", src="kernel")
        new_t = pkg("kernel-tools", "7.3.4-300.fc45", src="kernel",
                    changelog=[{"time": 10, "who": "a", "text": "Fix CVE-2026-9999"}])
        ch = [
            {"name": "kernel", "old": old_k, "new": new_k, "src": "kernel",
             "dir": "downgrade", "cls": S.classify_change(old_k, new_k, "F45", None)},
            {"name": "kernel-tools", "old": old_t, "new": new_t, "src": "kernel",
             "dir": "upgrade", "cls": S.classify_change(old_t, new_t, "F45", None)},
        ]
        diff = {"added": [], "removed": [], "changed": ch, "downgrades": [ch[0]],
                "count_a": 2, "count_b": 2}
        v = S.verdict_of(diff, LD, {})
        self.assertEqual(v["level"], "update-now")
        self.assertEqual(v["cves"], ["CVE-2026-9999"])
        self.assertEqual(v["security_pkgs"], ["kernel-tools"])
        self.assertEqual(v["downgrades"], ["kernel"])
        md = S.render_markdown("s", IMG, IMG, diff, LD, v, [])
        self.assertIn("CVE-2026-9999", md)
        self.assertIn("Downgrades in this update", md)


if __name__ == "__main__":
    unittest.main()
