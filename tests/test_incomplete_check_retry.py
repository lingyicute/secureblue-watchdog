"""Partial advisory/backlog audits must not become permanent no-update checkpoints."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_sbwatch import S, _FakeResp, pkg
from test_check_state import _image


class TestIncompleteCheckRetry(unittest.TestCase):
    def test_small_budget_resumes_until_all_requested_sources_are_checked(self):
        old, current = _image(1), _image(2)
        with tempfile.TemporaryDirectory() as td:
            state, report, output = (Path(td) / n for n in ("state.json", "report.md", "outputs"))
            state.write_text(json.dumps(dict(old, version="1")))
            argv = ["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                    "--report", str(report), "--cache-dir", td, "--no-fast", "--max-bodhi", "1",
                    "--prune-days", "0"]

            def packages(reg, image, *args):
                return S.PackageTable({
                    "nano": pkg("nano", "8.0-1.fc45" if image["digest"] == old["digest"] else "8.1-1.fc45"),
                    "curl": pkg("curl", "8.21.0-9.fc45"),
                    "openssl": pkg("openssl", "4.0.3-1.fc45"),
                })

            def resolve(reg, ref, light=False):
                return dict(current if ref == "latest" else old, ref=ref)

            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S.time, "sleep"), \
                    patch.object(S.urllib.request, "urlopen", side_effect=lambda *a, **kw: _FakeResp(
                        b'{"updates": [], "total": 0}')) as http, \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                for skipped in (2, 1, 0):
                    output.write_text("")
                    self.assertEqual(S.main(argv), 0)
                    payload = json.loads(Path(str(report) + ".json").read_text())
                    self.assertNotEqual(payload["verdict"]["level"], "no-update")
                    self.assertEqual(payload["from_digest"], old["digest"])
                    self.assertEqual(payload["backlog_coverage"]["skipped_queries"], skipped)
                    saved = json.loads(state.read_text())
                    self.assertEqual(saved.get("analysis_incomplete"), skipped > 0)
                    self.assertEqual(payload["analysis_incomplete"], skipped > 0)
                self.assertEqual(http.call_count, 3)
                output.write_text("")
                self.assertEqual(S.main(argv), 0)
                self.assertIn("verdict=no-update\n", output.read_text())
                self.assertEqual(http.call_count, 3)

    def test_new_target_keeps_last_usable_baseline_after_partial_analysis(self):
        old, partial, current = (_image(n) for n in (1, 2, 3))
        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            state.write_text(json.dumps({"digest": partial["digest"], "prev_digest": old["digest"],
                                         "prev_label": "last usable", "last_verdict": "consider",
                                         "analysis_incomplete": True}))
            images = {"latest": current, old["digest"]: old, partial["digest"]: partial}
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=lambda reg, ref: dict(images[ref], ref=ref)), \
                    patch.object(S, "load_pkglist", side_effect=lambda reg, image, *a: S.PackageTable({
                        "nano": pkg("nano", f"8.{image['digest'][7]}-1.fc45")})), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(S.main(["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                                         "--report", str(report), "--cache-dir", td, "--no-fast",
                                         "--no-audit", "--no-bodhi", "--prune-days", "0"]), 0)
            payload = json.loads(Path(str(report) + ".json").read_text())
            self.assertEqual(payload["from_digest"], old["digest"])
            self.assertEqual(payload["digest"], current["digest"])

    def test_transient_gaps_need_retry_but_explicit_scope_limits_do_not(self):
        for field in ("failed", "skipped", "truncated"):
            with self.subTest(diff=field):
                self.assertTrue(S._analysis_needs_retry({"verdict": {"level": "consider"},
                                                         "bodhi_state": {field: 1}}))
        for field in ("failed", "skipped_queries", "truncated"):
            with self.subTest(backlog=field):
                self.assertTrue(S._analysis_needs_retry({"verdict": {"level": "no-change"},
                                                         "backlog_coverage": {field: 1}}))
        self.assertFalse(S._analysis_needs_retry({"verdict": {"level": "skip"},
                                                  "bodhi_state": {"disabled": 1}}))
        self.assertFalse(S._analysis_needs_retry({"verdict": {"level": "skip"},
                                                  "backlog_coverage": {"skipped": 5}}))
        self.assertTrue(S._analysis_needs_retry({"verdict": {"level": "unknown"}}))

    def test_legacy_checkpoint_is_revalidated_once(self):
        old, current = _image(1), _image(2)
        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            state.write_text(json.dumps({"digest": current["digest"], "prev_digest": old["digest"],
                                         "prev_label": "last usable", "last_verdict": "consider"}))
            images = {"latest": current, old["digest"]: old}
            argv = ["check", "--image", "x/y", "--scan", "0", "--state", str(state),
                    "--report", str(report), "--cache-dir", td, "--no-fast", "--no-audit",
                    "--no-bodhi", "--prune-days", "0"]
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=lambda reg, ref: dict(images[ref], ref=ref)), \
                    patch.object(S, "load_pkglist", side_effect=lambda reg, image, *a: S.PackageTable({
                        "nano": pkg("nano", f"8.{image['digest'][7]}-1.fc45")})), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(S.main(argv), 0)
                payload = json.loads(Path(str(report) + ".json").read_text())
                self.assertEqual(payload["from_digest"], old["digest"])
                self.assertFalse(json.loads(state.read_text())["analysis_incomplete"])
                self.assertEqual(S.main(argv), 0)
                payload = json.loads(Path(str(report) + ".json").read_text())
                self.assertEqual(payload["verdict"]["level"], "no-update")
