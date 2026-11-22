"""A first observed build can seed a later comparison without becoming no-update."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, pkg
from test_check_state import _image


class TestInitialWatchBaseline(unittest.TestCase):
    def test_first_observation_can_be_baseline_for_the_next_distinct_build(self):
        old, new = _image(1), _image(2)
        watched = [old]
        def resolve(reg, ref, light=False):
            return dict(watched[0] if ref == "latest" else old, ref=ref)
        def packages(reg, image, *unused):
            return S.PackageTable({"trivalent": pkg("trivalent", image["annotations"][
                "org.opencontainers.image.version"] + ".0-1")})
        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            argv = ["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                    "--report", str(report), "--cache-dir", td, "--no-fast", "--no-audit",
                    "--no-bodhi", "--prune-days", "0"]
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S, "tag_exists", return_value=None), \
                    patch.object(S, "gh_outputs"), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                for _ in range(2):
                    self.assertEqual(S.main(argv), 0)
                    self.assertEqual(json.loads(state.read_text())["last_verdict"], "unknown")
                watched[0] = new
                self.assertEqual(S.main(argv), 0)
                payload = json.loads(Path(str(report) + ".json").read_text())
                self.assertEqual(payload["verdict"]["level"], "update-now")
                self.assertEqual(payload["from_digest"], old["digest"])
                self.assertEqual(payload["digest"], new["digest"])
                self.assertNotIn("baseline_missing", json.loads(state.read_text()))
