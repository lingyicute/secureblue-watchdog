"""Bodhi publishes numeric build epochs separately from NVR strings."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, FakeBodhi, _FakeResp

FIXTURE = json.loads((Path(__file__).parent / "fixtures/live_20261117.json").read_text())


class TestBuildEpochs(unittest.TestCase):
    def test_zero_epoch_survives_normalization(self):
        api = S.Bodhi(sleep=0)
        b = {"nvr": "dnf5-5.4.8.0-2.fc45", "type": "rpm", "epoch": 0}
        data = json.dumps({"updates": [{"builds": [b]}], "total": 1}).encode()
        with patch.object(S.urllib.request, "urlopen", return_value=_FakeResp(data)):
            self.assertEqual(api.updates_for_src("dnf5", "F45")[0]["build_epochs"], {b["nvr"]: "0"})

    def test_epoch_only_transition_is_not_an_old_fix(self):
        target = FIXTURE["images"]["new"]["packages"]["dnf5"]
        adv = dict(FIXTURE["dnf5_advisory"], build_epochs={target["nvr"]: "1"})
        result = S.classify_change(target, dict(target, epoch="1"), "F45", FakeBodhi({"dnf5": [adv]}))
        self.assertTrue(result["has_security_erratum"])
        self.assertFalse(result["already_had"])

    def test_source_epoch_precedes_version(self):
        p = FIXTURE["images"]["new"]["packages"]["dnf5"]
        self.assertTrue(S._is_behind(p, "1", "1.fc45", candidate_epoch=1))
        self.assertFalse(S._is_behind(dict(p, epoch="1"), "99", "1.fc45", candidate_epoch=0))
        self.assertTrue(S._is_behind(dict(p, epoch="1"), "99", "1.fc45", candidate_epoch=None))

    def test_subpackage_epoch_is_not_source_epoch(self):
        p = dict(FIXTURE["images"]["new"]["packages"]["dnf5"], name="dnf5-libs", epoch="8")
        self.assertIsNone(S._comparable_epoch(p))
        self.assertTrue(S._is_behind(dict(p, source_epoch="0"), "1", "1.fc45", candidate_epoch=1))


class TestBacklogEpochProvenance(unittest.TestCase):
    def test_epoch_and_severity_can_be_traced_to_their_respective_builds(self):
        from test_sbwatch import pkg
        old = dict(pkg("openssl", "3.5.7-1.fc43", epoch="1"), source_epoch="1")
        latest = "openssl-3.5.9-1.fc43"
        previous = "openssl-3.5.8-1.fc43"
        base = {"status": "stable", "type": "security"}
        updates = [dict(base, alias="previous", nvrs=[previous], build_epochs={previous: "1"},
                        severity="urgent", notes="text for previous only"),
                   dict(base, alias="FEDORA-2026-93eed17997", nvrs=[latest], build_epochs={latest: "1"},
                        severity="high")]
        rows, _ = S.security_backlog({"openssl": old}, "F43", FakeBodhi({"openssl": updates}))
        row, = rows
        self.assertEqual((row["have"], row["want"]), ("1:3.5.7-1.fc43", "1:3.5.9-1.fc43"))
        self.assertEqual((row["alias"], row["severity"], row["notes"]),
                         ("FEDORA-2026-93eed17997", "urgent", ""))
        self.assertEqual([a["severity"] for a in row["advisories"]], ["urgent", "high"])
