"""Unversioned Bodhi caches cannot establish complete CVE coverage."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestLegacyBodhiCache(unittest.TestCase):
    def _legacy(self, directory):
        path = Path(directory) / "bodhi-webkitgtk_F45.json"
        path.write_text(json.dumps([{"alias": "FEDORA-2026-test", "type": "security",
                                     "status": "stable", "severity": "high", "nvrs": [],
                                     "notes": "clipped", "cves": []}]))
        return path

    def test_legacy_cache_is_refetched_and_replaced_with_complete_cves(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = self._legacy(directory)
            bodhi = S.Bodhi(cache_dir=directory, sleep=0, max_calls=1)
            self.assertEqual(Path(bodhi._cf("webkitgtk-F45")), cache)
            doc = {"total": 1, "updates": [{"alias": "FEDORA-2026-test", "type": "security",
                    "status": "stable", "severity": "high", "builds": [],
                    "notes": "x" * 1600 + " CVE-2026-12345", "bugs": []}]}
            with patch.object(S._OPENER, "open",
                              return_value=io.BytesIO(json.dumps(doc).encode())) as request:
                updates = bodhi.updates_for_src("webkitgtk", "F45")
                self.assertEqual(updates[0]["cves"], ["CVE-2026-12345"])
                self.assertEqual(bodhi.updates_for_src("webkitgtk", "F45"), updates)
            self.assertEqual(request.call_count, 1)
            saved = json.loads(cache.read_text())
            self.assertEqual(saved["cache_version"], S.BODHI_CACHE_VERSION)
            self.assertEqual(saved["updates"], updates)

    def test_budget_exhaustion_does_not_fall_back_to_incomplete_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            self._legacy(directory)
            bodhi = S.Bodhi(cache_dir=directory, max_calls=0)
            with patch.object(S._OPENER, "open", side_effect=AssertionError("network")):
                self.assertEqual(bodhi.updates_for_src("webkitgtk", "F45"), [])
            self.assertEqual(bodhi.skipped, 1)

    def test_unknown_cache_versions_are_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            bodhi = S.Bodhi(cache_dir=directory, max_calls=0)
            path = Path(bodhi._cf("webkitgtk-F45"))
            path.write_text(json.dumps({"cache_version": S.BODHI_CACHE_VERSION + 1,
                                        "total": 0, "truncated": False, "updates": []}))
            self.assertIsNone(bodhi._read_cache_entry(str(path)))


if __name__ == "__main__":
    unittest.main()

    def test_invalid_cached_build_epochs_or_total_are_refetched(self):
        base = {"cache_version": S.BODHI_CACHE_VERSION, "fetched_at": 10**9,
                "total": 1, "truncated": False, "updates": [{
                    "alias": "FEDORA-2026-1", "type": "security", "status": "stable",
                    "severity": "high", "title": "", "notes": "", "cves": [],
                    "bugs": [], "nvrs": ["re2-1-1.fc45"], "build_epochs": {"re2-1-1.fc45": "2"}}]}
        cases = [
            {"build_epochs": {"re2-1-1.fc45": "0"}},
            {"build_epochs": {"re2-1-1.fc45": 2}},
            {"build_epochs": {"re2-1-1.fc45": "abc"}},
            {"build_epochs": {"re2-1-1.fc45": "02"}},
            {"build_epochs": {"": "2"}},
            {"total": True},
            {"total": -1},
        ]
        for bad in cases:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as cache:
                entry = json.loads(json.dumps(base))
                if "total" in bad:
                    entry["total"] = bad["total"]
                else:
                    entry["updates"][0]["build_epochs"] = bad["build_epochs"]
                client = S.Bodhi(cache_dir=cache, max_calls=1, sleep=0)
                cf = client._cf("re2-F45")
                with open(cf, "w", encoding="utf-8") as fh:
                    json.dump(entry, fh)
                self.assertIsNone(client._read_cache_entry(cf))
