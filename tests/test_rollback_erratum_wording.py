"""A rollback's headline must not say that no erratum was found while it names
the security errata the rollback reverts."""
import unittest

from test_sbwatch import S, pkg


def _verdict(changed):
    # A same-version chunk change of a security-sensitive package puts the verdict
    # on its "consider" branch, as glibc and selinux-policy did when the live
    # 45.20261123.0 was compared back to 45.20261119.0.
    diff = {"changed": changed, "added": [], "removed": [], "count_a": 3, "count_b": 3}
    chunks = [{"components": ["rpm/glibc"], "size": 4096, "stability": 0.0}]
    ldiff = {"download_bytes": 4096, "changed_chunks": chunks}
    return S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff))


class TestRollbackErratumWording(unittest.TestCase):
    def test_a_rollback_does_not_claim_that_no_erratum_was_found(self):
        # runc as the live image had it: 1.5.3-1.fc45 shipped FEDORA-2026-531ddf5058
        gone = {"alias": "FEDORA-2026-531ddf5058", "type": "security", "severity": "high",
                "status": "stable", "nvr": "runc-1.5.3-1.fc45", "also_matches_target": False}
        v = _verdict([{"name": "runc", "old": pkg("runc", "1.5.3-1.fc45"),
                       "new": pkg("runc", "1.5.2-3.fc45"), "src": "runc", "dir": "downgrade",
                       "cls": {"already_had": [gone]}}])
        self.assertEqual(v["level"], "consider")
        self.assertIn("reverts published security errata: FEDORA-2026-531ddf5058", v["headline"])
        self.assertIn("no CVE/erratum found among the upgrades, but", v["headline"])
        self.assertNotIn("for this delta", v["headline"])
        self.assertIn("升级部分未发现 CVE/勘误", v["headline_zh"])
        self.assertNotIn("此差异未发现", v["headline_zh"])

    def test_without_a_rollback_the_whole_delta_is_meant(self):
        v = _verdict([])
        self.assertEqual(v["level"], "consider")
        self.assertIn("no CVE/erratum found for this delta, but", v["headline"])
        self.assertIn("此差异未发现 CVE/勘误", v["headline_zh"])


if __name__ == "__main__":
    unittest.main()
