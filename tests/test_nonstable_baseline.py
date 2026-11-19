"""An obsolete update can have been published to updates-testing."""
import unittest
from test_sbwatch import S, FakeBodhi, pkg


class TestNonstableBaseline(unittest.TestCase):
    def test_obsolete_match_is_not_recorded_as_a_stable_fix_already_owned(self):
        old, new = pkg("dnf5", "5.4.7.0-1.fc45"), pkg("dnf5", "5.4.8.0-2.fc45")
        record = {"alias": "obsolete-record", "type": "bugfix", "status": "obsolete",
                  "severity": "unspecified", "nvrs": [old["nvr"]], "cves": []}
        result = S.classify_change(old, new, "F45", FakeBodhi({"dnf5": [record]}))
        self.assertFalse(result["already_had"])
        self.assertEqual(result["not_pushed"][0]["status"], "obsolete")
        self.assertIn("not stable", " ".join(result["why"]))
        self.assertFalse(result["security"])
