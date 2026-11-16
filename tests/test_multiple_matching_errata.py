"""A later non-security or lower-severity erratum must not overwrite a security one."""
import unittest

from test_sbwatch import S, pkg


class _Bodhi:
    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestMultipleMatchingErrata(unittest.TestCase):
    def test_security_erratum_survives_trailing_bugfix_erratum(self):
        ups = [
            {"alias": "FEDORA-2026-sec", "type": "security", "severity": "high",
             "status": "stable", "title": "", "notes": "sec", "cves": ["CVE-2026-1000"],
             "bugs": [], "date_approved": None, "nvrs": ["foo-1.2-1.fc45"]},
            {"alias": "FEDORA-2026-bug", "type": "bugfix", "severity": "low",
             "status": "stable", "title": "", "notes": "bug", "cves": [],
             "bugs": [], "date_approved": None, "nvrs": ["foo-1.2-1.fc45"]},
        ]
        cls = S.classify_change(pkg("foo", "1.1-1.fc45"), pkg("foo", "1.2-1.fc45"),
                                "F45", _Bodhi(ups))
        self.assertEqual(cls["bodhi_type"], "security")
        self.assertEqual(cls["erratum"]["alias"], "FEDORA-2026-sec")
        self.assertEqual(cls["aliases"], ["FEDORA-2026-sec", "FEDORA-2026-bug"])


if __name__ == "__main__":
    unittest.main()
