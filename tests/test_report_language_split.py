"""Chinese and English halves of the markdown report must not leak into each other."""
import re
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}
IMG = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}


class _Bodhi:
    def updates_for_src(self, src, release):
        return [{"alias": "FEDORA-2026-dnf5", "type": "security", "severity": "high",
                 "status": "stable", "title": "", "notes": "",
                 "cves": ["CVE-2026-123177"], "bugs": [], "date_approved": None,
                 "nvrs": ["dnf5-5.4.8.0-2.fc45"]}]


class TestReportLanguageSplit(unittest.TestCase):
    def test_english_half_contains_no_cjk_on_security_erratum_update(self):
        d = S.pkg_diff({"dnf5": pkg("dnf5", "5.4.7.0-1.fc45")},
                       {"dnf5": pkg("dnf5", "5.4.8.0-2.fc45",
                                    changelog=[{"time": 9, "text": "Fix CVE-2026-123177"}])})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", _Bodhi())
        g = S.group_by_src(d["changed"])
        v = S.verdict_of(d, LD, {}, {}, groups=g)
        zh, en = S.render_markdown("subj", IMG, IMG, d, LD, v, [], groups=g).split("\n\n---\n\n")
        self.assertIsNone(re.search(r"[\u4e00-\u9fff]", en), en)
        self.assertIn("`dnf5`: 安全勘误", zh)
        self.assertNotIn("security erratum 安全勘误", zh)
        self.assertIn("`dnf5`: security erratum", en)


if __name__ == "__main__":
    unittest.main()
