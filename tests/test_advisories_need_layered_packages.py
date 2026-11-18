"""The advisory arm of secureblue's notification rule needs layered packages."""
import unittest

from test_sbwatch import S, pkg, FakeBodhi, _upd_for

LD = {"download_bytes": 1024, "total_size_b": 4096, "chunks_a": 2, "chunks_b": 2,
      "chunks_changed": 1, "chunks_reused": 1, "download_pct": 25, "changed_chunks": [],
      "changed_packages_from_chunks": []}
IMG = {"ref": "x", "digest": "sha256:" + "1" * 64, "created": "2026-01-01T00:00:00Z",
       "annotations": {}}
CURL_URGENT = ("curl", "8.0-1.fc45", "8.1-1.fc45", [_upd_for("curl-8.1-1.fc45")])


def _change(name, old, new, updates):
    o, n = pkg(name, old), pkg(name, new)
    return {"name": name, "old": o, "new": n, "src": name, "dir": "upgrade",
            "cls": S.classify_change(o, n, "F45", FakeBodhi({name: updates}))}


def _analyse(*changes):
    changed = [_change(*c) for c in changes]
    diff = {"changed": changed, "added": [], "removed": [], "count_a": 1, "count_b": 1}
    groups = S.group_by_src(changed)
    return diff, groups, S.verdict_of(diff, LD, {}, groups=groups)


class TestAdvisoriesNeedLayeredPackages(unittest.TestCase):
    def test_an_advisory_alone_pops_nothing_on_a_stock_system(self):
        _diff, _groups, v = _analyse(CURL_URGENT)
        sbn = v["secureblue_notification"]
        self.assertEqual(sbn["level"], "major")
        self.assertEqual(sbn["level_without_advisories"], "none")
        self.assertTrue(sbn["advisory_driven"])
        self.assertIn("a stock system gets no notification", v["headline"])
        self.assertIn("默认安装不弹通知", v["headline_zh"])

    def test_the_kernel_arm_is_all_a_stock_system_keeps(self):
        _diff, _groups, v = _analyse(("kernel", "7.3.3-300.fc45", "7.3.4-300.fc45", []),
                                     CURL_URGENT)
        sbn = v["secureblue_notification"]
        self.assertEqual((sbn["level"], sbn["level_without_advisories"]), ("major", "normal"))
        self.assertIn("the normal notification for the kernel alone", v["headline"])
        self.assertIn("默认安装只因内核升级弹出普通通知", v["headline_zh"])

    def test_kernel_and_trivalent_do_not_depend_on_advisories(self):
        _diff, _groups, v = _analyse(("trivalent", "157.0-1", "158.0-1", []))
        sbn = v["secureblue_notification"]
        self.assertEqual((sbn["level"], sbn["level_without_advisories"]), ("major", "major"))
        self.assertFalse(sbn["advisory_driven"])
        self.assertNotIn("stock system", v["headline"])

    def test_the_report_names_the_stock_outcome(self):
        diff, groups, v = _analyse(CURL_URGENT)
        md = S.render_markdown("t", IMG, IMG, diff, LD, v, [], groups=groups)
        self.assertIn("on a system without layered packages (a stock install): none", md)
        self.assertIn("未叠加软件包的系统（默认安装）: 无 (none)", md)

    def test_registry_only_check_does_not_generate_a_base_diff(self):
        diff, groups, v = _analyse(CURL_URGENT)
        n = v["secureblue_notification"]
        self.assertEqual(n["delivery"]["stock_oci_without_staged_deployment"], "none")
        self.assertIn("staged OCI deployment", n["delivery"]["requires"])
        self.assertFalse(n["rpm_md_observed"])
        md = S.render_markdown("t", IMG, IMG, diff, LD, v, [], groups=groups)
        self.assertIn("a cached manifest alone has no base RPM diff", md)
        self.assertIn("older stable records may no longer be there", md)

    def test_equal_unread_rpmdb_does_not_identify_update_backend(self):
        v = S.verdict_of({"count_a": "?", "count_b": "?", "same_rpmdb": True,
                          "changed": [], "added": [], "removed": []}, LD, {})
        self.assertEqual(v["level"], "no-change")
        self.assertEqual(v["secureblue_notification"]["level"], "unknown")


if __name__ == "__main__":
    unittest.main()
