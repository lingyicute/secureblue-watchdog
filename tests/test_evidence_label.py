"""`security_basis` names the evidence that really set a group's security flag."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}
CHANGELOG = "changelog CVE 更新日志 CVE"


def erratum(alias, nvr, severity="unspecified", cves=()):
    return {"alias": alias, "type": "bugfix", "severity": severity, "status": "stable",
            "title": nvr, "notes": "", "cves": list(cves), "bugs": [],
            "date_approved": None, "date_stable": None, "nvrs": [nvr]}


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return [dict(u) for u in self._ups]


def verdict(ups, new_log=()):
    old = pkg("glib2", "2.84.1-1.fc45")
    new = pkg("glib2", "2.84.2-1.fc45", changelog=new_log)
    d = S.pkg_diff({"glib2": old}, {"glib2": new})
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45", _Bodhi(ups))
    return S.verdict_of(d, LD, {"kernel_a": "k", "kernel_b": "k"}, {})


class TestEvidenceLabel(unittest.TestCase):
    def test_a_high_severity_bugfix_erratum_is_no_changelog_cve(self):
        v = verdict([erratum("FEDORA-2026-bug", "glib2-2.84.2-1.fc45", severity="high")])
        self.assertEqual(v["level"], "update-now")
        self.assertIn("non-security erratum", v["security_basis"]["glib2"])
        self.assertNotIn("changelog CVE", v["security_basis"]["glib2"])
        self.assertNotIn("changelog CVE", v["headline"])
        self.assertNotIn("更新日志 CVE", v["headline_zh"])

    def test_cve_ids_listed_by_a_bugfix_erratum_are_no_changelog_cve(self):
        v = verdict([erratum("FEDORA-2026-bug", "glib2-2.84.2-1.fc45",
                             cves=["CVE-2026-1111"])])
        self.assertEqual(v["cves"], ["CVE-2026-1111"])
        self.assertIn("non-security erratum", v["security_basis"]["glib2"])

    def test_a_cve_in_the_new_changelog_keeps_its_label(self):
        v = verdict([erratum("FEDORA-2026-bug", "glib2-2.84.2-1.fc45", severity="high")],
                    new_log=[{"time": 5, "text": "- Fix CVE-2026-2222"}])
        self.assertEqual(v["security_basis"]["glib2"], CHANGELOG)

    def test_without_any_erratum_the_changelog_is_the_evidence(self):
        v = verdict([], new_log=[{"time": 5, "text": "- Fix CVE-2026-2222"}])
        self.assertEqual(v["security_basis"]["glib2"], CHANGELOG)


if __name__ == "__main__":
    unittest.main()
