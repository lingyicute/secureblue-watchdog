"""A downgrade reverts the erratum of the build it leaves, not of the one it gets."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}


def erratum(alias, nvr, type_="security", status="stable"):
    return {"alias": alias, "type": type_, "severity": "high", "status": status,
            "title": nvr, "notes": "", "cves": [], "bugs": [], "date_approved": None,
            "date_stable": None, "nvrs": [nvr]}


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return [dict(u) for u in self._ups]


def downgrade_lines(ups):
    """The `curl` line of the downgrade section, (zh, en)."""
    old, new = pkg("curl", "8.9.1-1.fc45"), pkg("curl", "8.9.0-1.fc45")
    d = S.pkg_diff({"curl": old}, {"curl": new})
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45", _Bodhi(ups))
    groups = S.group_by_src(d["changed"])
    v = S.verdict_of(d, LD, {"kernel_a": "k", "kernel_b": "k"}, {}, groups=groups)
    img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}}
    halves = S.render_markdown("s", img, img, d, LD, v, [], groups=groups).split("\n\n---\n\n")
    return [next(ln for ln in half.splitlines() if ln.startswith("- **curl**:"))
            for half in halves]


class TestDowngradeRevertedErratum(unittest.TestCase):
    def test_names_the_erratum_of_the_build_the_downgrade_leaves(self):
        zh, en = downgrade_lines([erratum("FEDORA-2026-left", "curl-8.9.1-1.fc45"),
                                  erratum("FEDORA-2026-target", "curl-8.9.0-1.fc45")])
        self.assertIn("reverts* a published erratum: FEDORA-2026-left", en)
        self.assertIn("回退*已发布的勘误: FEDORA-2026-left", zh)
        self.assertNotIn("FEDORA-2026-target", en)
        self.assertNotIn("FEDORA-2026-target", zh)

    def test_the_target_builds_own_erratum_is_never_called_reverted(self):
        zh, en = downgrade_lines([erratum("FEDORA-2026-left", "curl-8.9.1-1.fc45",
                                          type_="bugfix"),
                                  erratum("FEDORA-2026-target", "curl-8.9.0-1.fc45")])
        self.assertNotIn("reverts", en)
        self.assertNotIn("回退", zh)

    def test_an_unpushed_erratum_is_not_a_published_one(self):
        zh, en = downgrade_lines([erratum("FEDORA-2026-left", "curl-8.9.1-1.fc45",
                                          status="testing")])
        self.assertNotIn("reverts", en)
        self.assertNotIn("回退", zh)


if __name__ == "__main__":
    unittest.main()
