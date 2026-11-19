"""An incomplete errata query is not evidence of an empty advisory list."""
import unittest
from test_sbwatch import S, pkg
from test_live_20261117 import FIXTURE


class TestPartialPopup(unittest.TestCase):
    def predict(self, name, state):
        if name == "dnf5":
            a, b = [FIXTURE["images"][x]["packages"][name] for x in ("old", "new")]
        else:
            a, b = pkg(name, "1-1.fc45"), pkg(name, "2-1.fc45")
        diff = S.pkg_diff({name: a}, {name: b})
        return S.verdict_of(diff, {"download_bytes": 0}, {}, bodhi_state=state)["secureblue_notification"]

    def test_live_dnf5_without_lookup_is_not_a_negative_prediction(self):
        for reason in ({"disabled": 1}, {"failed": 1}, {"skipped": 1}, {"truncated": ["dnf5"]}):
            with self.subTest(reason=reason):
                result = self.predict("dnf5", reason)
                self.assertEqual(result["level"], "unknown")
                self.assertEqual(result["level_without_advisories"], "none")
                self.assertIsNone(result["security_advisory_count"])
                self.assertIsNone(result["max_advisory_severity"])

    def test_kernel_remains_normal_on_stock_install(self):
        result = self.predict("kernel", {"unavailable": 1})
        self.assertEqual((result["level"], result["level_without_advisories"]), ("unknown", "normal"))

    def test_trivalent_is_already_at_the_maximum(self):
        self.assertEqual(self.predict("trivalent", {"skipped": 1})["level"], "major")
