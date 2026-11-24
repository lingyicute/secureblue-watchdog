"""A cross-release rollback can leave a stable advisory in the old Bodhi release."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


FIXTURE = json.loads((Path(__file__).parent / "fixtures/live_20261117.json").read_text())
OLD = {**FIXTURE["images"]["new"]["packages"]["dnf5"], "changelog": []}
NEW = pkg("dnf5", "5.4.6.0-1.fc44")
ADVISORY = FIXTURE["dnf5_advisory"]


def compare(bodhi):
    a = {"ref": "F45", "annotations": {}, "digest": "old", "layers": []}
    b = {"ref": "F44", "annotations": {}, "digest": "new", "layers": []}
    args = SimpleNamespace(exact=1, keep_order=True, no_bodhi=False, max_bodhi=2,
                           cache_dir=None)
    with patch.object(S, "load_pkglist", side_effect=[{"dnf5": OLD}, {"dnf5": NEW}]), \
            patch.object(S, "Bodhi", return_value=bodhi):
        return S.do_diff(args, "F45", "F44", images=(a, b), reg=SimpleNamespace(_token=lambda: None))


class Bodhi:
    failed = skipped = 0
    truncated_src = ()

    def __init__(self, advisories):
        self.advisories = advisories
        self.queries = []

    def updates_for_src(self, src, release):
        self.queries.append((src, release))
        if release == "F45":
            if self.advisories is None:
                self.failed += 1
                return []
            return self.advisories
        return []


class TestRollbackBaselineRelease(unittest.TestCase):
    def test_f45_dnf5_erratum_is_reported_as_left_not_gained(self):
        bodhi = Bodhi([ADVISORY])
        res = compare(bodhi)
        self.assertEqual(bodhi.queries, [("dnf5", "F44"), ("dnf5", "F45")])
        verdict = res["verdict"]
        self.assertEqual(verdict["errata_reverted"], [ADVISORY["alias"]])
        self.assertEqual(verdict["cves"], [])
        self.assertEqual(verdict["secureblue_notification"]["level"], "none")
        exported = S._comparison_json(res)
        self.assertEqual(exported["changed"][0]["already_had"][0]["release"], "F45")

    def test_an_advisory_covering_both_endpoints_is_not_left(self):
        res = compare(Bodhi([{**ADVISORY, "nvrs": [*ADVISORY["nvrs"], NEW["nvr"]]}]))
        self.assertTrue(res["diff"]["changed"][0]["cls"]["already_had"][0]["also_matches_target"])
        self.assertEqual(res["verdict"]["errata_reverted"], [])

    def test_old_scope_failure_retries_without_tainting_target_notification(self):
        res = compare(Bodhi(None))
        self.assertTrue(S._analysis_needs_retry(res))
        self.assertEqual(res["verdict"]["secureblue_notification"]["level"], "none")
