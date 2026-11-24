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

    def test_markdown_reports_incomplete_severity_instead_of_not_read(self):
        a, b = [FIXTURE["images"][x]["packages"]["dnf5"] for x in ("old", "new")]
        diff = S.pkg_diff(
            {"dnf5": a, "trivalent": pkg("trivalent", "1-1.fc45")},
            {"dnf5": b, "trivalent": pkg("trivalent", "2-1.fc45")},
        )
        for c in diff["changed"]:
            if c["name"] == "dnf5":
                c["cls"] = S.classify_change(
                    c["old"], c["new"], "F45",
                    type("B", (), {"updates_for_src": lambda self, s, r: [FIXTURE["dnf5_advisory"]]})(),
                )
        ldiff = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
                 "total_size_b": 0, "download_bytes": 0, "download_pct": 0, "changed_chunks": []}
        verdict = S.verdict_of(diff, ldiff, {}, bodhi_state={"skipped": 1})
        sbn = verdict["secureblue_notification"]
        self.assertIsNone(sbn["max_advisory_severity"])
        self.assertEqual(sbn["observed_max_advisory_severity"], "important")
        img = {"ref": "x", "digest": "sha256:" + "1" * 64, "annotations": {}}
        md = S.render_markdown("s", img, img, diff, ldiff, verdict, [])
        self.assertIn("unknown (incomplete advisory coverage; highest observed: important)", md)
        self.assertIn("未知（勘误覆盖不完整；已读最高等级：important）", md)
        self.assertNotIn("`not read`", md)
        self.assertNotIn("`未读取`", md)

    def test_secureblue_kernel_rebuild_never_attaches_fedora_advisory_even_without_bodhi(self):
        old = dict(pkg("kernel", "7.3.3-300.secureblue.1.fc45"), vendor="")
        new = dict(pkg("kernel", "7.3.4-300.secureblue.1.fc45"), vendor="")
        diff = S.pkg_diff({"kernel": old}, {"kernel": new})
        result = S.verdict_of(diff, {"download_bytes": 0}, {},
                              bodhi_state={"disabled": 1})["secureblue_notification"]
        self.assertEqual((result["level"], result["level_without_advisories"]),
                         ("normal", "normal"))
        self.assertEqual(result["max_advisory_severity"], "none")
