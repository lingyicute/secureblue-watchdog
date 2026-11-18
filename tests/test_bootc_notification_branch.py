"""The bootc branch of secureblue's security-update-notification script.

Upstream checks `[[ -f /usr/bin/rpm-ostree ]]` before anything else: without it
the script reads /run/bootc/status.json (written by bootc alone) and notifies
for every staged update (urgency=critical, "An update is ready"), never looking
at an rpm diff. The prediction has to follow the *booted* image - the old side
of a diff - and that popup must not escalate the verdict, since it carries no
information about the update itself. A table with neither package (a stripped
fixture) stays on the rpm-ostree model.
"""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}


def _routine_diff():
    d = S.pkg_diff({"nano": pkg("nano", "8.1-1.fc45")},
                   {"nano": pkg("nano", "8.2-1.fc45")})
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
    return d


class TestBootcNotificationBranch(unittest.TestCase):
    def test_old_image_without_rpm_ostree_predicts_unconditional_popup(self):
        d = _routine_diff()
        d["bootc_only_old"] = True
        sbn = S.secureblue_notification(d)
        self.assertEqual(sbn["level"], "major")
        self.assertEqual(sbn["message"], "An update is ready")
        self.assertTrue(sbn["unconditional"])
        self.assertFalse(sbn["advisory_driven"])
        self.assertEqual(sbn["level_without_advisories"], "major")
        self.assertTrue(any("bootc" in w for w in sbn["why"]))

    def test_unconditional_popup_does_not_escalate_the_verdict(self):
        d = _routine_diff()
        d["bootc_only_old"] = True
        v = S.verdict_of(d, LD, {}, {})
        self.assertEqual(v["level"], "skip")
        self.assertNotIn("escalated_by_secureblue_rule", v)
        self.assertNotIn("classifies this as major", v["level_basis"])
        self.assertIn('MAJOR notification: "An update is ready"', v["headline"])
        self.assertIn("「An update is ready」", v["headline_zh"])

    def test_rpm_ostree_model_applies_when_the_flag_is_absent_or_true(self):
        for flag in ({}, {"bootc_only_old": False}):
            d = dict(_routine_diff(), **flag)
            sbn = S.secureblue_notification(d)
            self.assertEqual(sbn["level"], "none")
            self.assertNotIn("unconditional", sbn)

    def test_trivalent_bump_still_escalates_on_an_rpm_ostree_image(self):
        d = S.pkg_diff({"trivalent": pkg("trivalent", "157.0.8103.78-448613")},
                       {"trivalent": pkg("trivalent", "157.0.8103.78-448700")})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", None)
        d["bootc_only_old"] = False
        v = S.verdict_of(d, LD, {}, {})
        self.assertEqual(v["level"], "update-now")
        # trivalent is a security-sensitive source, so the pre-escalation level
        self.assertEqual(v["escalated_by_secureblue_rule"], "consider")

    def test_bootc_does_not_guarantee_delivery(self):
        d = dict(_routine_diff(), bootc_only_old=True)
        v = S.verdict_of(d, LD, {}, {})
        delivery = v["secureblue_notification"]["delivery"]
        self.assertFalse(delivery["observed"])
        self.assertEqual(delivery["suppress_if_notified_today"], ["critical"])
        self.assertIn("may show", v["headline"])
        self.assertIn("可能", v["headline_zh"])

    def test_normal_rule_is_suppressed_by_either_daily_stamp(self):
        pred = S.secureblue_notification({"changed": [{"name": "kernel", "dir": "upgrade"}]})
        self.assertEqual(pred["delivery"]["suppress_if_notified_today"], ["critical", "normal"])

    def test_do_diff_flags_a_bootc_only_old_image(self):
        src = open(S.__file__, encoding="utf-8").read()
        self.assertIn('diff["bootc_only_old"] = "bootc" in pa and "rpm-ostree" not in pa',
                      src)


if __name__ == "__main__":
    unittest.main()
