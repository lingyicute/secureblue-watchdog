"""A non-security erratum that makes a package security-relevant is named as evidence."""
import unittest

from test_sbwatch import S, pkg, FakeBodhi

# FEDORA-2026-78aa6059e7 as Bodhi serves it: a bugfix update ranked `high`
ERRATUM = {"alias": "FEDORA-2026-78aa6059e7", "type": "bugfix", "severity": "high",
           "status": "stable", "nvrs": ["shadow-utils-4.20.0-2.fc45"]}
LINE = "erratum/勘误 FEDORA-2026-78aa6059e7: type=bugfix severity={} status=stable"


def classify(erratum):
    return S.classify_change(pkg("shadow-utils", "4.19.0-7.fc45"),
                             pkg("shadow-utils", "4.20.0-2.fc45"), "F45",
                             FakeBodhi({"shadow-utils": [erratum]}))


class TestNonSecurityErratumEvidence(unittest.TestCase):
    def test_high_severity_bugfix_is_named(self):
        cls = classify(ERRATUM)
        self.assertTrue(cls["security"])
        self.assertFalse(cls["has_security_erratum"])
        self.assertEqual(cls["why"], [LINE.format("high")])

    def test_bugfix_listing_a_cve_is_named(self):
        cls = classify(dict(ERRATUM, severity="unspecified", notes="fixes CVE-2026-12345"))
        self.assertTrue(cls["security"])
        self.assertEqual(cls["why"], [LINE.format("unspecified")])

    def test_plain_bugfix_adds_no_evidence(self):
        cls = classify(dict(ERRATUM, severity="unspecified"))
        self.assertFalse(cls["security"])
        self.assertEqual(cls["why"], [])


if __name__ == "__main__":
    unittest.main()
