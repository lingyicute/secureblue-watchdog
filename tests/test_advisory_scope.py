"""Bodhi bugs belong to the whole advisory, not every rebuild in a side tag."""
import unittest

from test_sbwatch import S, pkg


class MassRebuild:
    failed = skipped = 0

    def updates_for_src(self, src, release):
        # Representative subset of the 490 public builds in this advisory.
        return [{"alias": "FEDORA-2026-91259c13b9", "type": "security",
                 "status": "stable", "severity": "medium", "cves": ["CVE-2026-84975"],
                 "nvrs": ["libxml2-2.15.4-1.fc45", "webkitgtk-2.54.0-3.fc45"]}]


class TestAdvisoryScope(unittest.TestCase):
    def test_advisory_ids_are_visible_but_not_attributed_to_dependent_source(self):
        old, new = pkg("webkitgtk", "2.54.0-2.fc45"), pkg("webkitgtk", "2.54.0-3.fc45")
        change = S.classify_change(old, new, "F45", MassRebuild())
        self.assertTrue(change["security"])
        self.assertEqual(change["cves"], [])
        self.assertEqual(change["advisory_wide_cves"], ["CVE-2026-84975"])
        diff = S.pkg_diff({old["name"]: old}, {new["name"]: new})
        diff["changed"][0]["cls"] = change
        v = S.verdict_of(diff, {"download_bytes": 0}, {})
        self.assertEqual(v["cves"], ["CVE-2026-84975"])
        self.assertEqual(v["advisory_wide_cves"], v["cves"])
        self.assertNotIn("gains security fixes", v["headline"])

    def test_backlog_keeps_multi_source_ids_separate(self):
        p = pkg("webkitgtk", "2.54.0-2.fc45")
        rows, _ = S.security_backlog({p["name"]: p}, "F45", MassRebuild())
        self.assertEqual(rows[0]["cves"], [])
        self.assertEqual(rows[0]["advisory_wide_cves"], ["CVE-2026-84975"])
