"""Offline regression against the signed images and Bodhi response captured in audit."""
import json
from pathlib import Path
import unittest
from test_sbwatch import S, FakeBodhi

FIXTURE = json.loads((Path(__file__).parent / "fixtures/live_20261117.json").read_text())


class TestLiveAuditSnapshot(unittest.TestCase):
    def test_real_dnf5_security_advisory_and_cve(self):
        old, new = (FIXTURE["images"][side]["packages"]["dnf5"] for side in ("old", "new"))
        cls = S.classify_change(old, new, "F45", FakeBodhi({"dnf5": [FIXTURE["dnf5_advisory"]]}))
        self.assertTrue(cls["has_security_erratum"])
        self.assertIn("CVE-2026-123177", cls["cves"])
        self.assertIn("FEDORA-2026-b9a53ff63c", cls["aliases"])

    def test_real_glibc_chunk_moves_at_the_same_version(self):
        a, b = (FIXTURE["images"][side] for side in ("old", "new"))
        diff = S.pkg_diff({"glibc": a["packages"]["glibc"]}, {"glibc": b["packages"]["glibc"]})
        layers = S.layer_diff({"layers": a["glibc_layers"]}, {"layers": b["glibc_layers"]})
        self.assertEqual(diff["changed"], [])
        self.assertGreater(layers["download_bytes"], 0)
        xc = S.crosscheck_chunks(layers, diff)
        self.assertEqual(S.verdict_of(diff, layers, {}, xc)["level"], "consider")

    def test_real_restricted_bubblewrap_is_not_a_fedora_build(self):
        package = FIXTURE["images"]["new"]["packages"]["bubblewrap"]
        self.assertTrue(S._is_third_party(package))
        self.assertEqual(S.nvr_candidates_split(package)[1], [])


if __name__ == "__main__":
    unittest.main()
