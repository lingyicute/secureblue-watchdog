"""A rollback can cross security builds that neither endpoint installed."""
import unittest
from types import SimpleNamespace
from test_sbwatch import S, pkg


# Observed in /updates/?packages=nss&releases=F45 on 2026-11-22.
ADVISORY = {"alias": "FEDORA-2026-9b9d903069", "type": "security", "status": "stable",
            "severity": "urgent", "nvrs": ["nss-3.129.0-1.fc45"], "notes": "", "cves": []}


def package(version, release="1.fc45", name="nss"):
    return dict(pkg(name, version + "-" + release), source_epoch="0", vendor="Fedora Project")


class TestRollbackInterval(unittest.TestCase):
    def classify(self, advisory=None, baseline="F45", old=None, new=None):
        old, new = old or package("3.133.0"), new or package("3.128.0")
        bodhi = SimpleNamespace(updates_for_src=lambda *a: [advisory or ADVISORY])
        cls = S.classify_change(old, new, "F45", bodhi, baseline_release=baseline)
        diff = S.pkg_diff({old["name"]: old}, {new["name"]: new})
        diff["changed"][0]["cls"] = cls
        return cls, diff

    def test_real_intermediate_nss_erratum_is_reverted_not_gained(self):
        cls, diff = self.classify()
        self.assertEqual([a["alias"] for a in cls.get("reverted_errata", [])], [ADVISORY["alias"]])
        verdict = S.verdict_of(diff, S.layer_diff({"layers": []}, {"layers": []}), {})
        self.assertEqual(verdict["errata_reverted"], [ADVISORY["alias"]])
        self.assertEqual(verdict["level"], "consider")
        self.assertEqual(verdict["cves"], [])
        self.assertFalse(cls["has_security_erratum"])
        self.assertEqual(verdict["secureblue_notification"]["level"], "none")

    def test_reverted_advisory_cves_survive_json_without_becoming_new_fixes(self):
        advisory = dict(ADVISORY, cves=["CVE-2026-12345"])
        cls, diff = self.classify(advisory)
        image = {"ref": "test", "digest": "sha256:" + "a" * 64, "annotations": {}}
        data = S._comparison_json({"a": image, "b": image, "diff": diff,
                                 "layers": {"download_bytes": 0}, "verdict": {}})
        evidence = data["changed"][0].get("reverted_errata", [])
        self.assertEqual(evidence[0]["cves"], advisory["cves"])
        self.assertFalse(data["changed"][0]["security"])
        self.assertEqual(data["changed"][0]["cves"], [])
        self.assertEqual(cls["aliases"], [])

    def test_bounds_status_type_and_branch_are_respected(self):
        for change in ({"nvrs": ["nss-3.127.0-1.fc45"]},
                       {"nvrs": ["nss-3.134.0-1.fc45"]}, {"status": "testing"},
                       {"type": "bugfix"}, {"nvrs": ["nss-3.129.0-1.fc44"]}):
            with self.subTest(change=change):
                cls, _ = self.classify(dict(ADVISORY, **change))
                self.assertEqual(cls.get("reverted_errata", []), [])
        cls, _ = self.classify(baseline="F44")
        self.assertEqual(cls.get("reverted_errata", []), [])

    def test_normalised_kernel_rollback_crosses_fedora_security_build(self):
        old = package("7.3.4", "300.secureblue.1.fc45", "kernel")
        new = package("7.3.2", "300.secureblue.1.fc45", "kernel")
        advisory = dict(ADVISORY, alias="FEDORA-2026-655049a906",
                        severity="medium", nvrs=["kernel-7.3.3-300.fc45"])
        cls, _ = self.classify(advisory, old=old, new=new)
        self.assertEqual([a["nvr"] for a in cls.get("reverted_errata", [])], advisory["nvrs"])
