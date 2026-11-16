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


if __name__ == "__main__":
    unittest.main()
