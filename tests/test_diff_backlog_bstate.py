"""Backlog Bodhi failures and budget limits must not contaminate the diff verdict."""
import types
import unittest

from test_sbwatch import S, pkg


class TestDiffBacklogBstate(unittest.TestCase):
    def test_backlog_failure_and_budget_skip_do_not_escalate_clean_diff(self):
        class Reg:
            def _token(self):
                return None

        class SharedBodhi:
            def __init__(self, **kw):
                self.failed = 0
                self.skipped = 0
                self.truncated_src = set()
                self.time_limited = False
                self._mem = {}

            def updates_for_src(self, src, rel):
                key = f"{src}-{rel}"
                if src == "nano":
                    self._mem[key] = {"total": 0, "truncated": False, "updates": [], "unqueried": None}
                    return []
                if src == "openssh":
                    self.failed += 1
                    self._mem[key] = {"total": None, "truncated": False, "updates": [], "unqueried": "failed"}
                    return []
                self.skipped += 1
                self.time_limited = True
                self._mem[key] = {"total": None, "truncated": False, "updates": [], "unqueried": "skipped"}
                return []

        pa = S.PackageTable({
            "nano": pkg("nano", "8.0-1.fc45"),
            "openssh": pkg("openssh", "9.9-1.fc45"),
            "curl": pkg("curl", "8.9-1.fc45"),
        })
        pb = S.PackageTable({
            "nano": pkg("nano", "8.1-1.fc45"),
            "openssh": pkg("openssh", "9.9-1.fc45"),
            "curl": pkg("curl", "8.9-1.fc45"),
        })
        img_a = {"ref": "a", "digest": "sha256:" + "1" * 64, "created": "2026-11-19T00:00:00Z",
                 "annotations": {}, "layers": []}
        img_b = {"ref": "b", "digest": "sha256:" + "2" * 64, "created": "2026-11-20T00:00:00Z",
                 "annotations": {}, "layers": []}
        args = types.SimpleNamespace(exact=1, keep_order=True, no_bodhi=False, audit=True,
                                     max_bodhi=10, bodhi_seconds=60, backlog_candidates=None,
                                     cache_dir=None, cosign_pub=None)
        orig_load, orig_bodhi = S.load_pkglist, S.Bodhi
        S.load_pkglist = lambda reg, img, *a: pa if img["digest"] == img_a["digest"] else pb
        S.Bodhi = SharedBodhi
        try:
            res = S.do_diff(args, "a", "b", images=(img_a, img_b), reg=Reg())
        finally:
            S.load_pkglist, S.Bodhi = orig_load, orig_bodhi

        self.assertEqual(res["verdict"]["level"], "skip")
        self.assertNotIn("CAUTION: errata coverage incomplete", res["verdict"]["headline"])
        self.assertEqual(res["backlog_coverage"]["failed"], 1)
        self.assertEqual(res["backlog_coverage"]["skipped_queries"], 1)
        notes_en = "\n".join(n.en for n in res["notes"])
        self.assertIn("1 failed", notes_en)
        self.assertIn("1 not queried", notes_en)
        self.assertNotIn("judged from changelog CVEs only", notes_en)


if __name__ == "__main__":
    unittest.main()
