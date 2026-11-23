"""Bodhi publishes numeric build epochs separately from NVR strings."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, FakeBodhi, _FakeResp, pkg

FIXTURE = json.loads((Path(__file__).parent / "fixtures/live_20261117.json").read_text())

# Live 2026-11-23: the installed Fedora RPM re2-20251105-19.fc45 carries Epoch 2
# (so do aardvark-dns and netavark 2.1.0-1.fc45), yet Bodhi lists each of those
# builds with "epoch": 0.
RE2 = {"name": "re2", "version": "20251105", "release": "19.fc45", "epoch": "2",
       "arch": "x86_64", "srpm": "re2-20251105-19.fc45", "src": "re2",
       "vendor": "Fedora Project", "evr": "20251105-19.fc45",
       "nvr": "re2-20251105-19.fc45", "source_epoch": "2", "changelog": []}


def _bodhi(*updates):
    """Serve `updates` as Bodhi's /updates/ answer to the real client."""
    data = json.dumps({"updates": list(updates), "total": len(updates)}).encode()
    return patch.object(S.urllib.request, "urlopen", return_value=_FakeResp(data))


def _security(nvr, epoch, alias="FEDORA-2026-0000000000"):
    return {"alias": alias, "type": "security", "status": "stable", "severity": "high",
            "builds": [{"nvr": nvr, "type": "rpm", "epoch": epoch}]}


class TestBuildEpochs(unittest.TestCase):
    def test_only_an_epoch_bodhi_states_is_recorded(self):
        builds = [{"nvr": "dnf5-5.4.8.0-2.fc45", "type": "rpm", "epoch": 0},
                  {"nvr": "vim-9.2.127-1.fc45", "type": "rpm", "epoch": 2}]
        with _bodhi({"builds": builds}):
            update, = S.Bodhi(sleep=0).updates_for_src("dnf5", "F45")
        self.assertEqual(update["build_epochs"], {"vim-9.2.127-1.fc45": "2"})

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


class TestBodhiDefaultEpoch(unittest.TestCase):
    def test_installed_build_matches_its_own_erratum(self):
        old = dict(RE2, release="18.fc45", srpm="re2-20251105-18.fc45",
                   evr="20251105-18.fc45", nvr="re2-20251105-18.fc45")
        with _bodhi(_security(RE2["nvr"], 0)):
            result = S.classify_change(old, RE2, "F45", S.Bodhi(sleep=0))
        self.assertTrue(result["has_security_erratum"])
        self.assertEqual(result["aliases"], ["FEDORA-2026-0000000000"])

    def test_backlog_reports_a_newer_build(self):
        have = dict(pkg("openssl", "3.5.7-1.fc45", epoch="1"), source_epoch="1")
        with _bodhi(_security("openssl-3.5.9-1.fc45", 0)):
            rows, _ = S.security_backlog({"openssl": have}, "F45", S.Bodhi(sleep=0))
        self.assertEqual([(r["have"], r["want"]) for r in rows],
                         [("1:3.5.7-1.fc45", "3.5.9-1.fc45")])

    def test_backlog_names_the_newest_build_when_only_some_epochs_are_stated(self):
        have = dict(pkg("openssl", "3.5.7-1.fc45", epoch="1"), source_epoch="1")
        with _bodhi(_security("openssl-3.5.8-1.fc45", 1, "FEDORA-2026-1111111111"),
                    _security("openssl-3.5.9-1.fc45", 0, "FEDORA-2026-2222222222")):
            rows, _ = S.security_backlog({"openssl": have}, "F45", S.Bodhi(sleep=0))
        self.assertEqual([(r["want"], r["alias"]) for r in rows],
                         [("3.5.9-1.fc45", "FEDORA-2026-2222222222")])


class TestBacklogEpochProvenance(unittest.TestCase):
    def test_epoch_and_severity_can_be_traced_to_their_respective_builds(self):
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
