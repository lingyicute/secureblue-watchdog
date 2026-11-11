"""Security errata of the builds an update passes over on its way from old to new."""
import unittest

from test_sbwatch import S


def rpm(name, version, release, src=None):
    src = src or name
    return {"name": name, "version": version, "release": release, "epoch": "",
            "arch": "x86_64", "src": src, "srpm": f"{src}-{version}-{release}",
            "evr": f"{version}-{release}", "nvr": f"{name}-{version}-{release}",
            "changelog": []}


def erratum(alias, nvr, type_="security", severity="high", status="stable", cves=()):
    return {"alias": alias, "type": type_, "severity": severity, "status": status,
            "title": nvr, "notes": "", "cves": list(cves), "bugs": [],
            "date_approved": None, "date_stable": None, "nvrs": [nvr]}


class FakeBodhi:
    def __init__(self, updates):
        self.updates = updates

    def updates_for_src(self, src, release):
        return self.updates


OLD = rpm("curl", "8.9.0", "1.fc45")
NEW = rpm("curl", "8.9.1", "3.fc45")


def classify(updates, old=OLD, new=NEW):
    return S.classify_change(old, new, "F45", FakeBodhi(updates))


class TestPassedOverErrata(unittest.TestCase):
    def test_a_security_erratum_of_a_passed_over_build_is_a_fix_gained(self):
        info = classify([
            erratum("FEDORA-2026-mid", "curl-8.9.1-1.fc45", cves=["CVE-2026-1000"]),
            erratum("FEDORA-2026-new", "curl-8.9.1-3.fc45", type_="bugfix",
                    severity="unspecified"),
        ])
        self.assertTrue(info["security"])
        self.assertEqual(info["cves"], ["CVE-2026-1000"])
        self.assertEqual([x["alias"] for x in info["passed_over"]], ["FEDORA-2026-mid"])
        self.assertEqual(info["sev_rank"], 3)
        self.assertEqual(info["aliases"], ["FEDORA-2026-new"])
        # rpm-ostree attaches an advisory to the exact build only
        self.assertFalse(info["has_security_erratum"])

    def test_builds_outside_the_range_are_not_gained_by_this_update(self):
        info = classify([
            erratum("FEDORA-2026-older", "curl-8.8.0-2.fc45", cves=["CVE-2026-1"]),
            erratum("FEDORA-2026-newer", "curl-8.9.2-1.fc45", cves=["CVE-2026-2"]),
            erratum("FEDORA-2026-other", "libcurl-8.9.1-1.fc45", cves=["CVE-2026-3"]),
        ])
        self.assertFalse(info["security"])
        self.assertEqual((info["cves"], info["passed_over"]), ([], []))

    def test_only_pushed_security_errata_count(self):
        info = classify([
            erratum("FEDORA-2026-testing", "curl-8.9.1-1.fc45", status="testing",
                    cves=["CVE-2026-1"]),
            erratum("FEDORA-2026-bugfix", "curl-8.9.1-2.fc45", type_="bugfix",
                    cves=["CVE-2026-2"]),
        ])
        self.assertFalse(info["security"])
        self.assertEqual((info["cves"], info["passed_over"]), ([], []))

    def test_a_downgrade_passes_over_nothing(self):
        info = classify([erratum("FEDORA-2026-mid", "curl-8.9.1-1.fc45",
                                 cves=["CVE-2026-1000"])], old=NEW, new=OLD)
        self.assertFalse(info["security"])
        self.assertEqual(info["passed_over"], [])

    def test_a_secureblue_rebuild_passes_over_fedora_builds_of_its_source(self):
        old = rpm("kernel-core", "7.2.5", "200.secureblue.1.fc45", src="kernel")
        new = rpm("kernel-core", "7.2.7", "200.secureblue.1.fc45", src="kernel")
        info = classify([
            erratum("FEDORA-2026-had", "kernel-7.2.5-200.fc45"),
            erratum("FEDORA-2026-mid", "kernel-7.2.6-200.fc45", severity="urgent"),
        ], old=old, new=new)
        self.assertEqual([x["alias"] for x in info["already_had"]], ["FEDORA-2026-had"])
        self.assertEqual([x["nvr"] for x in info["passed_over"]], ["kernel-7.2.6-200.fc45"])
        self.assertTrue(info["security"])
        self.assertFalse(info["has_security_erratum"])

    def test_a_build_of_another_fedora_release_is_not_passed_over(self):
        # across a rebase the release numbers of the two branches do not order:
        # the fc44 build may well carry the fix its fc45 twin got an erratum for
        old = rpm("bluez", "5.87", "1.fc44")
        new = rpm("bluez", "5.88", "1.fc45")
        info = classify([erratum("FEDORA-2026-twin", "bluez-5.87-1.fc45"),
                         erratum("FEDORA-2026-next", "bluez-5.87-3.fc45")], old=old, new=new)
        self.assertFalse(info["security"])
        self.assertEqual(info["passed_over"], [])

    def test_the_verdict_rises_while_the_notification_prediction_does_not(self):
        info = classify([erratum("FEDORA-2026-mid", "curl-8.9.1-1.fc45", severity="urgent")])
        changed = [{"name": "curl", "old": OLD, "new": NEW, "src": "curl",
                    "dir": "upgrade", "cls": info}]
        diff = {"changed": changed, "added": [], "removed": [], "count_a": 1, "count_b": 1}
        v = S.verdict_of(diff, {"download_bytes": 0, "changed_chunks": []}, {})
        self.assertEqual(v["level"], "update-now")
        self.assertIn("passed-over build", v["security_basis"]["curl"])
        self.assertEqual(v["secureblue_notification"]["level"], "none")


if __name__ == "__main__":
    unittest.main()
