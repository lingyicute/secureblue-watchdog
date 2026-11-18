"""The headline of a rollback names the security errata it reverts."""
import unittest

from test_sbwatch import S, pkg, FakeBodhi

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 0, "chunks_reused": 1,
      "total_size_b": 100, "download_bytes": 0, "download_pct": 0,
      "changed_packages_from_chunks": [], "changed_chunks": []}
# Bodhi's two assimp errata on F45; the live tag moved back past the first one
LEFT = {"alias": "FEDORA-2026-123b7cacad", "type": "security", "severity": "unspecified",
        "status": "stable", "nvrs": ["assimp-6.0.6-1.fc45"]}
TARGET = {"alias": "FEDORA-2026-022956c3bb", "type": "security", "severity": "medium",
          "status": "stable", "nvrs": ["assimp-6.0.5-6.fc45"]}


def verdict(old_evr, new_evr, left=LEFT):
    d = S.pkg_diff({"assimp": pkg("assimp", old_evr)}, {"assimp": pkg("assimp", new_evr)})
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F45",
                                     FakeBodhi({"assimp": [left, TARGET]}))
    return S.verdict_of(d, LD, {}, {})


class TestRollbackRevertedErrata(unittest.TestCase):
    def test_the_erratum_of_the_build_being_left_is_named(self):
        v = verdict("6.0.6-1.fc45", "6.0.5-6.fc45")
        self.assertEqual(v["errata_reverted"], ["FEDORA-2026-123b7cacad"])
        self.assertIn("WARNING: this update downgrades assimp (6.0.6-1.fc45 → 6.0.5-6.fc45) "
                      "- this reverts published security errata: FEDORA-2026-123b7cacad",
                      v["headline"])
        self.assertIn("——这会回退已发布的安全勘误：FEDORA-2026-123b7cacad", v["headline_zh"])
        # the erratum of the build it moves back TO is not reverted
        self.assertNotIn("FEDORA-2026-022956c3bb", v["headline"])

    def test_other_types_and_unpushed_errata_are_not_named(self):
        for change in ({"type": "bugfix"}, {"status": "testing"}):
            v = verdict("6.0.6-1.fc45", "6.0.5-6.fc45", dict(LEFT, **change))
            self.assertEqual(v["errata_reverted"], [], change)
            self.assertNotIn("this reverts", v["headline"])

    def test_an_upgrade_reverts_nothing(self):
        v = verdict("6.0.5-6.fc45", "6.0.6-1.fc45")
        self.assertEqual(v["errata_reverted"], [])
        self.assertNotIn("this reverts", v["headline"])


if __name__ == "__main__":
    unittest.main()
