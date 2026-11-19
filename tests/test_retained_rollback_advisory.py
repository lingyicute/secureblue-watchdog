"""A local kernel release rollback need not cross a Fedora security build."""
import unittest
from test_sbwatch import S, FakeBodhi, pkg


class TestRetainedRollbackAdvisory(unittest.TestCase):
    def test_same_normalized_fedora_build_retains_its_advisory(self):
        old = pkg("kernel", "7.3.3-300.secureblue.2.fc45")
        new = pkg("kernel", "7.3.3-300.secureblue.1.fc45")
        advisory = {"alias": "kernel-fix", "type": "security", "status": "stable",
                    "severity": "high", "cves": [], "nvrs": ["kernel-7.3.3-300.fc45"]}
        d = S.pkg_diff({"kernel": old}, {"kernel": new})
        d["changed"][0]["cls"] = S.classify_change(old, new, "F45", FakeBodhi({"kernel": [advisory]}))
        v = S.verdict_of(d, {"download_bytes": 0}, {})
        self.assertEqual(v["downgrades"], ["kernel"])
        self.assertEqual(v["errata_reverted"], [])
        self.assertNotIn("reverts published", v["headline"])

    def test_only_downgraded_members_supply_reverted_evidence(self):
        def change(direction, alias):
            return {"dir": direction, "cls": {"already_had": [
                {"alias": alias, "type": "security", "status": "stable"}]}}
        group = {"pkgs": [change("upgrade", "kept"), change("downgrade", "left")]}
        self.assertEqual(S._reverted_aliases(group), ["left"])
