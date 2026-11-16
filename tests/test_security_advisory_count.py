"""secureblue_notification counts distinct attached security advisories."""
import unittest

from test_sbwatch import S, pkg


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestSecurityAdvisoryCount(unittest.TestCase):
    def test_one_advisory_spanning_several_sources_is_counted_once(self):
        shared = [{"alias": "FEDORA-2026-kf6", "type": "security", "severity": "high",
                   "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
                   "date_approved": None,
                   "nvrs": ["kf6-6.32.0-1.fc45", "kf6-karchive-6.32.0-1.fc45",
                            "kf6-kimageformats-6.32.0-1.fc45"]}]
        names = ("kf6", "kf6-karchive", "kf6-kimageformats")
        d = S.pkg_diff({n: pkg(n, "6.31.0-1.fc45") for n in names},
                       {n: pkg(n, "6.32.0-1.fc45") for n in names})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", _Bodhi(shared))
        sbn = S.secureblue_notification(d)
        self.assertEqual(sbn["security_advisory_count"], 1)
        self.assertEqual(sbn["max_advisory_severity"], "important")

    def test_two_advisories_on_one_source_are_counted_separately(self):
        ups = [
            {"alias": "FEDORA-2026-a", "type": "security", "severity": "low",
             "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
             "date_approved": None, "nvrs": ["curl-8.9.2-1.fc45"]},
            {"alias": "FEDORA-2026-b", "type": "security", "severity": "urgent",
             "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
             "date_approved": None, "nvrs": ["curl-8.9.2-1.fc45"]},
        ]
        d = S.pkg_diff({"curl": pkg("curl", "8.9.1-1.fc45")},
                       {"curl": pkg("curl", "8.9.2-1.fc45")})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", _Bodhi(ups))
        sbn = S.secureblue_notification(d)
        self.assertEqual(sbn["security_advisory_count"], 2)
        self.assertEqual(sbn["max_advisory_severity"], "critical")


if __name__ == "__main__":
    unittest.main()
