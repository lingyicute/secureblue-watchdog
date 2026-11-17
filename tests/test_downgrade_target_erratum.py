"""Rolling back to an older build must not count that build's old erratum as a fix."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
      "total_size_b": 100, "download_bytes": 100, "download_pct": 100,
      "changed_packages_from_chunks": ["foo"], "changed_chunks": []}


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestDowngradeTargetErratum(unittest.TestCase):
    def test_downgrade_to_build_with_old_urgent_erratum_stays_consider(self):
        bodhi = _Bodhi([
            {"alias": "FEDORA-2026-oldcrit", "type": "security", "status": "stable",
             "severity": "urgent", "title": "", "notes": "CVE-2026-1111",
             "cves": ["CVE-2026-1111"], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.1-1.fc45"]},
            {"alias": "FEDORA-2026-newsec", "type": "security", "status": "stable",
             "severity": "high", "title": "", "notes": "CVE-2026-2222",
             "cves": ["CVE-2026-2222"], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.2-1.fc45"]},
        ])
        old, new = pkg("foo", "1.2-1.fc45"), pkg("foo", "1.1-1.fc45")
        ch = [{"name": "foo", "old": old, "new": new, "src": "foo", "dir": "downgrade",
               "cls": S.classify_change(old, new, "F45", bodhi)}]
        diff = {"added": [], "removed": [], "changed": ch, "downgrades": ch,
                "count_a": 1, "count_b": 1}
        v = S.verdict_of(diff, LD, {})
        self.assertEqual(v["level"], "consider")
        self.assertEqual(v["secureblue_notification"]["level"], "none")
        self.assertEqual(v["already_had"], [])


if __name__ == "__main__":
    unittest.main()
