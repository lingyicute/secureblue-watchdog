"""level_basis erratum kind matches the erratum that actually reached the peak rank."""
import unittest

from test_sbwatch import S, FakeBodhi, pkg


class TestLevelBasisPeakSeverity(unittest.TestCase):
    def test_urgent_bugfix_next_to_high_security_is_not_called_4_of_4_security(self):
        pa = {"foo": pkg("foo", "1.0-1.fc45"), "bar": pkg("bar", "1.0-1.fc45")}
        pb = {"foo": pkg("foo", "1.1-1.fc45"), "bar": pkg("bar", "1.1-1.fc45")}
        bodhi = FakeBodhi({
            "foo": [{"alias": "FEDORA-2026-sec", "type": "security", "severity": "high",
                     "status": "stable", "nvrs": ["foo-1.1-1.fc45"], "cves": []}],
            "bar": [{"alias": "FEDORA-2026-bug", "type": "bugfix", "severity": "urgent",
                     "status": "stable", "nvrs": ["bar-1.1-1.fc45"], "cves": []}],
        })
        diff = S.pkg_diff(pa, pb)
        for c in diff["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F45", bodhi)
        v = S.verdict_of(diff, {"download_bytes": 0, "changed_chunks": []}, {})
        self.assertEqual(v["severity_rank"], 4)
        self.assertIn("non-security erratum ranks 4/4", v["level_basis"])
        self.assertNotIn("security erratum ranks 4/4", v["level_basis"].replace("non-security", ""))


if __name__ == "__main__":
    unittest.main()
