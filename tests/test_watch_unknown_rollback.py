"""An inconclusive image must not become the source of the next comparison."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sbwatch as S


class TestUnknownRollback(unittest.TestCase):
    def test_return_to_last_usable_image_does_not_compare_against_failure(self):
        good = "sha256:" + "1" * 64
        failed = "sha256:" + "2" * 64
        image = {"ref": "latest", "digest": good, "index_digest": good,
                 "annotations": {}, "created": "2026-11-17T00:00:00Z",
                 "layers": [{"digest": good, "components": ["bigfiles/rpmdb.sqlite"],
                             "stability": 0, "size": 1}]}
        with tempfile.TemporaryDirectory() as tmp:
            state, report = Path(tmp) / "state.json", Path(tmp) / "report.md"
            state.write_text(json.dumps({"digest": failed, "prev_digest": good,
                                         "last_verdict": "unknown"}))
            with patch.object(S.Registry, "_token", return_value=None), \
                 patch.object(S, "resolve", return_value=image) as resolve:
                self.assertEqual(S.main(["check", "--scan", "0", "--exact", "0",
                                         "--no-bodhi", "--cache-dir", tmp,
                                         "--state", str(state), "--report", str(report)]), 0)
            self.assertEqual([call.args[1] for call in resolve.call_args_list], ["latest"])
            data = json.loads(report.with_suffix(".md.json").read_text())
            self.assertEqual(data["from_digest"], good)
            self.assertEqual(data["verdict"]["level"], "no-change")
