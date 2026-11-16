"""Passed-over errata still match Fedora packages that carry no .fcNN dist tag."""
import unittest

from test_sbwatch import S, pkg


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


def _erratum(alias, nvr, cve):
    return {"alias": alias, "type": "security", "severity": "high", "status": "stable",
            "title": nvr, "notes": "", "cves": [cve], "bugs": [],
            "date_approved": None, "date_stable": None, "nvrs": [nvr]}


class TestDistlessPassedOver(unittest.TestCase):
    def test_shim_without_dist_tag_matches_distless_intermediate_erratum(self):
        # Live shim ships as shim-16.1-5 -> shim-16.1-7 with no .fcNN in rpmdb or Bodhi.
        cls = S.classify_change(
            pkg("shim-x64", "16.1-5", src="shim"),
            pkg("shim-x64", "16.1-7", src="shim"),
            "F45",
            _Bodhi([_erratum("FEDORA-2026-shim", "shim-16.1-6", "CVE-2026-7777"),
                    _erratum("FEDORA-2026-dist", "shim-16.1-6.fc45", "CVE-2026-8888")]))
        self.assertEqual([x["alias"] for x in cls["passed_over"]], ["FEDORA-2026-shim"])
        self.assertEqual(cls["cves"], ["CVE-2026-7777"])

    def test_distless_old_to_dist_tagged_new_does_not_claim_distless_erratum(self):
        cls = S.classify_change(
            pkg("foo", "1.0-1"),
            pkg("foo", "1.0-3.fc45"),
            "F45",
            _Bodhi([_erratum("FEDORA-2026-x", "foo-1.0-2", "CVE-2026-9999")]))
        self.assertEqual(cls["passed_over"], [])


if __name__ == "__main__":
    unittest.main()
