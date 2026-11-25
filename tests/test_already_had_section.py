"""The 'already had' errata section deduplicates aliases and excludes downgrades."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}
IMG = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestAlreadyHadSection(unittest.TestCase):
    def test_same_alias_matched_under_two_subpackage_nvrs_is_listed_once(self):
        ups = [{"alias": "FEDORA-2026-old", "type": "security", "severity": "medium",
                "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
                "date_approved": None, "nvrs": ["aaa-sub-1.0-1.fc45", "foo-1.0-1.fc45"]}]
        pa = {"aaa-sub": pkg("aaa-sub", "1.0-1.fc45", src="foo"),
              "foo": pkg("foo", "1.0-1.fc45", src="foo")}
        pb = {"aaa-sub": pkg("aaa-sub", "1.1-1.fc45", src="foo"),
              "foo": pkg("foo", "1.1-1.fc45", src="foo")}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", _Bodhi(ups))
        g = S.group_by_src(d["changed"])
        en = S.render_markdown("s", IMG, IMG, d, LD, S.verdict_of(d, LD, {}, {}, groups=g),
                               [], groups=g).split("\n\n---\n\n")[1]
        line = next(ln for ln in en.splitlines() if "the build you already had" in ln)
        self.assertEqual(line.count("FEDORA-2026-old"), 1)

    def test_reverted_downgrade_erratum_is_not_repeated_under_already_had(self):
        ups = [{"alias": "FEDORA-2026-left", "type": "security", "severity": "high",
                "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
                "date_approved": None, "nvrs": ["curl-8.9.1-1.fc45"]}]
        d = S.pkg_diff({"curl": pkg("curl", "8.9.1-1.fc45")},
                       {"curl": pkg("curl", "8.9.0-1.fc45")})
        d["changed"][0]["cls"] = S.classify_change(
            d["changed"][0]["old"], d["changed"][0]["new"], "F45", _Bodhi(ups))
        g = S.group_by_src(d["changed"])
        md = S.render_markdown("s", IMG, IMG, d, LD, S.verdict_of(d, LD, {}, {}, groups=g),
                               [], groups=g)
        self.assertIn("reverts* a published erratum: FEDORA-2026-left", md)
        self.assertNotIn("Errata you already had before this update", md)
        self.assertNotIn("本次更新之前你就已经拥有的勘误", md)

    def test_erratum_passed_over_by_sibling_srpm_is_excluded_from_already_had(self):
        ups = [{"alias": "FEDORA-2026-655049a906", "type": "security", "severity": "medium",
                "status": "stable", "title": "", "notes": "", "cves": [], "bugs": [],
                "date_approved": None, "nvrs": ["kernel-7.3.3-300.fc45"]}]
        pa = {"kernel": dict(pkg("kernel", "7.3.3-300.secureblue.2.fc45"), vendor=""),
              "kernel-tools": pkg("kernel-tools", "7.2.15-300.fc45", src="kernel")}
        pb = {"kernel": dict(pkg("kernel", "7.3.4-300.secureblue.1.fc45"), vendor=""),
              "kernel-tools": pkg("kernel-tools", "7.3.4-300.fc45", src="kernel")}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", _Bodhi(ups), baseline_release="F45")
        g = S.group_by_src(d["changed"])
        v = S.verdict_of(d, LD, {}, {}, groups=g)
        md = S.render_markdown("s", IMG, IMG, d, LD, v, [], groups=g)
        self.assertEqual(v["level"], "update-now")
        self.assertEqual(v["already_had"], [])
        self.assertNotIn("Errata you already had before this update", md)
        self.assertNotIn("本次更新之前你就已经拥有的勘误", md)


if __name__ == "__main__":
    unittest.main()
