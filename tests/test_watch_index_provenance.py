"""Watch artifacts keep the registry's top-level snapshot and its platform distinct."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sbwatch as S


def image(n, day):
    digest = "sha256:" + n * 64
    return {"ref": digest, "digest": digest, "index_digest": "sha256:" + n * 63 + "0",
            "annotations": {}, "created": f"2026-11-{day}T00:00:00Z",
            "layers": [{"digest": "sha256:" + "9" * 64, "components": ["rpmdb.sqlite"],
                        "size": 12, "stability": 0}]}


class TestWatchIndexProvenance(unittest.TestCase):
    def test_history_and_forced_reanalysis_use_top_level_digests(self):
        old, new = image("a", 17), image("b", 18)
        rows = [{"digest": old["index_digest"], "platform_digest": old["digest"],
                 "created": old["created"]}]
        registry = {old["index_digest"]: old, "latest": new}
        with tempfile.TemporaryDirectory() as tmp:
            state, report = Path(tmp) / "state.json", Path(tmp) / "report.md"
            argv = ["check", "--exact", "0", "--no-bodhi", "--cache-dir", tmp,
                    "--state", str(state), "--report", str(report)]
            with patch.object(S.Registry, "_token", return_value=None), \
                 patch.object(S, "resolve", side_effect=lambda r, ref: registry[ref]), \
                 patch.object(S, "build_history", return_value=rows), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                for extra in ([], ["--force", "--scan", "0"]):
                    self.assertEqual(S.main(argv + extra), 0)
                    data = json.loads(report.with_suffix(".md.json").read_text())
                    self.assertEqual(data["from_index_digest"], old["index_digest"])
                    self.assertEqual(data["from_digest"], old["digest"])
                self.assertEqual(json.loads(state.read_text())["prev_index_digest"], old["index_digest"])
