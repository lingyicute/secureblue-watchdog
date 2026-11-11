"""A watched tag rolling back must not be reported as a security upgrade."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestWatchDirection(unittest.TestCase):
    def _check(self, previous_version, target_version, extra=()):
        def image(version):
            digest = "sha256:" + str(version) * 64
            return {"digest": digest, "index_digest": digest,
                    "created": f"2026-01-0{version}T00:00:00Z", "layers": [],
                    "annotations": {"org.opencontainers.image.version": str(version)}}

        previous, current = image(previous_version), image(target_version)

        def resolve(reg, ref, light=False):
            return dict(current if ref == "latest" else previous, ref=ref)

        def packages(reg, img, ref, directory, notes):
            version = img["annotations"]["org.opencontainers.image.version"]
            log = [{"time": 2, "text": "Fix CVE-2026-12345"}] if version == "2" else []
            return S.PackageTable({"trivalent": pkg("trivalent", version + ".0-1.fc45",
                                                    changelog=log)})

        with tempfile.TemporaryDirectory() as directory:
            state, report, output = (Path(directory) / name for name in ("state.json", "report.md", "outputs"))
            state.write_text(json.dumps(dict(previous, version=str(previous_version))))
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S.urllib.request, "urlopen", side_effect=AssertionError("network")), \
                    patch.object(S._OPENER, "open", side_effect=AssertionError("network")), \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory, "--scan", "0",
                             "--no-fast", "--no-audit", "--no-bodhi", "--prune-days", "0", *extra])
            self.assertEqual(rc, 0)
            result = json.loads(Path(str(report) + ".json").read_text())
            saved = json.loads(state.read_text())
            self.assertEqual(saved["digest"], current["digest"])
            self.assertEqual(saved["prev_digest"], previous["digest"])
            return result, report.read_text(), output.read_text()

    def test_state_based_rollback_is_a_downgrade_not_a_security_upgrade(self):
        result, markdown, output = self._check(2, 1)
        self.assertEqual(result["changed"][0]["dir"], "downgrade")
        self.assertEqual(result["changed"][0]["old"], "2.0-1.fc45")
        self.assertEqual(result["changed"][0]["new"], "1.0-1.fc45")
        self.assertEqual(result["verdict"]["level"], "consider")
        self.assertEqual(result["verdict"]["secureblue_notification"]["level"], "none")
        self.assertEqual(result["verdict"]["cves"], [])
        self.assertEqual(result["verdict"]["cves_dropped"], ["CVE-2026-12345"])
        self.assertIn("Downgrades in this update", markdown)
        self.assertIn("verdict=consider\n", output)
        self.assertEqual(result["to"], "latest")

    def test_forward_tag_movement_still_reports_the_security_upgrade(self):
        result, _, _ = self._check(1, 2)
        self.assertEqual(result["changed"][0]["dir"], "upgrade")
        self.assertEqual(result["verdict"]["level"], "update-now")
        self.assertEqual(result["verdict"]["cves"], ["CVE-2026-12345"])

    def test_explicit_baseline_keeps_documented_auto_orientation(self):
        result, _, _ = self._check(2, 1, ["--a", "explicit"])
        self.assertEqual(result["changed"][0]["dir"], "upgrade")

    def test_keep_order_still_overrides_explicit_baseline_orientation(self):
        result, _, _ = self._check(2, 1, ["--a", "explicit", "--keep-order"])
        self.assertEqual(result["changed"][0]["dir"], "downgrade")


if __name__ == "__main__":
    unittest.main()
