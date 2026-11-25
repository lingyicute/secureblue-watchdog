"""security_backlog checks the SRPM build EVR for .secureblue.N markers."""
import unittest

from test_sbwatch import S, FakeBodhi, pkg


class TestBacklogSrpmSecureblue(unittest.TestCase):
    def test_subpackage_with_independent_release_inherits_srpm_secureblue_eligibility(self):
        sub = dict(pkg("nspr", "4.39.0-10.fc45", src="nss"),
                   srpm="nss-3.130.0-1.secureblue.1.fc45",
                   vendor="Fedora Copr - user secureblue")
        upd = {"nss": [{"alias": "FEDORA-2026-nss", "type": "security", "severity": "high",
                        "status": "stable", "nvrs": ["nss-3.133.0-1.fc45"], "notes": "",
                        "bugs": [], "title": "", "cves": []}]}
        rows, cov = S.security_backlog({"nspr": sub}, "F45", FakeBodhi(upd))
        self.assertEqual(cov["pool_ineligible"], [])
        self.assertEqual([r["src"] for r in rows], ["nss"])


if __name__ == "__main__":
    unittest.main()
