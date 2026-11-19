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


class SideTagRebuild:
    """Shape of FEDORA-2026-54c7ad647e, the stable F45 "OpenSSL 4.0 rebuild":
    type and severity `unspecified`, 738 builds, and the frr CVE bugs of one of
    them in its bug list."""
    failed = skipped = 0

    def updates_for_src(self, src, release):
        return [{"alias": "FEDORA-2026-54c7ad647e", "type": "unspecified",
                 "status": "stable", "severity": "unspecified",
                 "cves": ["CVE-2026-37457", "CVE-2026-37458", "CVE-2026-37459"],
                 "bugs": [{"title": "CVE-2026-37457 frr: denial of service via crafted "
                                    "FlowSpec component"}],
                 "notes": "OpenSSL 4.0 rebuild",
                 "nvrs": ["389-ds-base-3.3.0-4.fc45", "3proxy-0.9.6-2.fc45",
                          "frr-10.6.1-1.fc45"]}]


class TestNonSecuritySideTag(unittest.TestCase):
    def test_other_packages_cves_do_not_make_a_rebuild_security(self):
        old, new = pkg("3proxy", "0.9.6-1.fc45"), pkg("3proxy", "0.9.6-2.fc45")
        change = S.classify_change(old, new, "F45", SideTagRebuild())
        self.assertFalse(change["security"])
        self.assertEqual(change["cves"], [])
        self.assertEqual(change["advisory_wide_cves"], [])
        self.assertIn("FEDORA-2026-54c7ad647e", change["aliases"])
        diff = S.pkg_diff({old["name"]: old}, {new["name"]: new})
        diff["changed"][0]["cls"] = change
        v = S.verdict_of(diff, {"download_bytes": 0}, {})
        self.assertEqual(v["level"], "skip")
        self.assertEqual(v["cves"], [])
