"""The evidence cell leads with the evidence, not with the "no longer mentioned" hint."""
import unittest

from test_sbwatch import S, pkg, FakeBodhi

# openssl 3.5.9-1.fc44 -> 4.0.3-1.fc45 on the live F44 -> F45 rebase: 17 ids left the
# changelog, and the hint listing them pushed the erratum out of the 190-character cell
DROPPED = [{"time": i, "who": "a", "text": f"Fix CVE-2026-{10000 + i}"} for i in range(17)]
ERRATUM = {"alias": "FEDORA-2026-06c29a2cb4", "type": "security", "severity": "high",
           "status": "stable", "nvrs": ["openssl-4.0.3-1.fc45"]}
LINE = "FEDORA-2026-06c29a2cb4: type=security severity=high status=stable"


def image(n):
    return {"ref": f"r{n}", "digest": "sha256:" + str(n) * 64, "annotations": {}, "created": ""}


class TestEvidenceBeforeHint(unittest.TestCase):
    def test_the_erratum_precedes_the_hint(self):
        cls = S.classify_change(pkg("openssl", "3.5.9-1.fc45", changelog=DROPPED),
                                pkg("openssl", "4.0.3-1.fc45"), "F45",
                                FakeBodhi({"openssl": [ERRATUM]}))
        self.assertEqual(len(cls["cves_dropped"]), 17)
        self.assertEqual(cls["why"][0], "erratum/勘误 " + LINE)
        self.assertTrue(cls["why"][-1].startswith("no longer mentioned/不再提及: "))

    def test_changelog_cves_still_come_first(self):
        new_log = [{"time": 99, "who": "a", "text": "Fix CVE-2026-55555"}]
        cls = S.classify_change(pkg("openssl", "3.5.9-1.fc45", changelog=DROPPED),
                                pkg("openssl", "4.0.3-1.fc45", changelog=new_log), "F45", None)
        self.assertTrue(cls["why"][0].startswith("changelog CVEs/更新日志中的 CVE: "))
        self.assertTrue(cls["why"][-1].startswith("no longer mentioned/不再提及: "))

    def test_the_report_cell_shows_the_whole_erratum(self):
        diff = S.pkg_diff({"openssl": pkg("openssl", "3.5.9-1.fc45", changelog=DROPPED)},
                          {"openssl": pkg("openssl", "4.0.3-1.fc45")})
        for c in diff["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45",
                                         FakeBodhi({"openssl": [ERRATUM]}))
        layers = S.layer_diff({"layers": []}, {"layers": []})
        xc = S.crosscheck_chunks(layers, diff)
        groups = S.group_by_src(diff["changed"])
        verdict = S.verdict_of(diff, layers, {}, xc, groups=groups)
        md = S.render_markdown("t", image(1), image(2), diff, layers, verdict, [], xc,
                               None, groups)
        self.assertIn("| erratum " + LINE, md)
        self.assertIn("| 勘误 " + LINE, md)


if __name__ == "__main__":
    unittest.main()
