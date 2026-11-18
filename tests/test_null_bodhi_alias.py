"""Missing Bodhi update aliases must not crash verdict_of or render_markdown."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
      "total_size_b": 100, "download_bytes": 100, "download_pct": 100,
      "changed_packages_from_chunks": ["foo"], "changed_chunks": []}
IMG = {"ref": "a", "digest": "sha256:" + "0" * 64, "annotations": {}, "created": ""}


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestNullBodhiAlias(unittest.TestCase):
    def test_null_aliases_in_already_had_unpushed_and_bugfix_errata_do_not_crash(self):
        old, new = pkg("foo", "1.1-1.fc45"), pkg("foo", "1.2-1.fc45")
        bodhi = _Bodhi([
            {"alias": None, "type": "bugfix", "status": "stable", "severity": "high",
             "title": "", "notes": "", "cves": [], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.2-1.fc45"]},
            {"alias": None, "type": "security", "status": "testing", "severity": "high",
             "title": "", "notes": "", "cves": [], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.2-1.fc45"]},
            {"alias": None, "type": "security", "status": "stable", "severity": "low",
             "title": "", "notes": "", "cves": [], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.1-1.fc45"]},
            {"alias": "FEDORA-2026-prev", "type": "bugfix", "status": "stable",
             "severity": "low", "title": "", "notes": "", "cves": [], "bugs": [],
             "date_approved": None, "nvrs": ["foo-1.1-1.fc45"]},
        ])
        cls = S.classify_change(old, new, "F45", bodhi)
        diff = {"added": [], "removed": [], "downgrades": [], "count_a": 1, "count_b": 1,
                "changed": [{"name": "foo", "old": old, "new": new, "src": "foo",
                             "dir": "upgrade", "cls": cls}]}
        v = S.verdict_of(diff, LD, {})
        self.assertEqual(v["already_had"], ["FEDORA-2026-prev"])
        self.assertIn("non-security erratum", v["security_basis"]["foo"])
        md = S.render_markdown("s", IMG, IMG, diff, LD, v, [])
        self.assertIn("? (testing)", md)

    def test_updates_for_src_falls_back_to_updateid(self):
        bodhi = S.Bodhi(cache_dir=None, max_calls=1, sleep=0)
        raw = [{"alias": None, "updateid": "FEDORA-2026-fb", "type": "security",
                "status": "stable", "builds": [{"nvr": "foo-1.2-1.fc45"}]}]
        bodhi._fetch_page = lambda url, src, expected_page: ({"total": 1, "updates": raw}, raw)
        self.assertEqual(bodhi.updates_for_src("foo", "F45")[0]["alias"], "FEDORA-2026-fb")


if __name__ == "__main__":
    unittest.main()
