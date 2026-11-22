"""A disclosed scan cap still cannot justify an unqualified safe-to-skip verdict."""
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from test_sbwatch import S, pkg


class TestChangelogIncompleteVerdict(unittest.TestCase):
    def test_unread_cve_changes_verdict_and_survives_machine_readable_output(self):
        old = S.PackageTable({"nano": pkg("nano", "1-1.fc45")})
        new = S.PackageTable({"nano": pkg("nano", "2-1.fc45", changelog=[
            {"time": 2, "who": "Fedora", "text": "Routine change"},
            {"time": 1, "who": "Fedora", "text": "Fix CVE-2026-12345"}])})
        images = tuple({"ref": str(n), "digest": "sha256:" + str(n) * 64,
                        "annotations": {}, "layers": []} for n in (1, 2))
        bodhi = SimpleNamespace(updates_for_src=lambda *a: [], failed=0, skipped=0,
                                truncated_src=set(), time_limited=False)
        with tempfile.TemporaryDirectory() as td:
            args = SimpleNamespace(keep_order=True, exact=1, cache_dir=td,
                                   no_bodhi=False, max_bodhi=10, audit=False)
            with patch.object(S, "NEW_LOG_CAP", 1), \
                    patch.object(S, "load_pkglist", side_effect=[old, new]), \
                    patch.object(S, "Bodhi", return_value=bodhi):
                res = S.do_diff(args, "1", "2", images=images, reg=Mock())
        self.assertEqual(res["verdict"]["level"], "unknown")
        self.assertFalse(res["verdict"].get("changelog_coverage_complete", True))
        payload = S._comparison_json(res)
        self.assertEqual(payload.get("changelog_scan_incomplete"), ["nano"])
        self.assertEqual(payload["changed"][0]["changelog_scan"]["new_total"], 2)
