"""The stdout form of a JSON export is a single machine-readable document."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestJsonStdout(unittest.TestCase):
    def test_structured_stdout_for_all_export_commands(self):
        def resolve(_reg, ref):
            return {"ref": ref, "digest": ref, "layers": [],
                    "annotations": {"org.opencontainers.image.version": "45.20261124.0"}}

        cases = (
            (["layers", "old", "new", "--json"], "download_bytes"),
            (["pkgs", "new", "--json"], "packages"),
            (["diff", "old", "new", "--no-bodhi", "--json-out"], "verdict"),
            (["backlog", "new", "--json-out"], "coverage"),
        )
        with tempfile.TemporaryDirectory() as cache, patch.object(S, "resolve", side_effect=resolve), \
                patch.object(S.Registry, "_token"), patch.object(S, "load_pkglist", return_value={
                    "example": pkg("example", "1.0-1.fc45")}):
            for args, key in cases:
                for path in ("-", "/dev/stdout", "/dev/fd/1"):
                    with self.subTest(cmd=args[0], path=path):
                        out = StringIO()
                        with redirect_stdout(out), redirect_stderr(StringIO()):
                            self.assertEqual(S.main([*args, path, "--cache-dir", cache]), 0)
                        self.assertIn(key, json.loads(out.getvalue()))

            out = StringIO()
            report = Path(cache) / "diff.md"
            with redirect_stdout(out), redirect_stderr(StringIO()):
                self.assertEqual(S.main(["diff", "old", "new", "--no-bodhi", "--json-out", "-",
                                         "--markdown", str(report), "--cache-dir", cache]), 0)
            self.assertIn("verdict", json.loads(out.getvalue()))
            self.assertIn("##", report.read_text())

    def test_markdown_and_json_cannot_share_stdout(self):
        with redirect_stderr(StringIO()), patch.object(S, "resolve") as resolve:
            with self.assertRaises(SystemExit) as raised:
                S.main(["diff", "old", "new", "--markdown", "/dev/stdout", "--json-out", "-"])
            self.assertEqual(raised.exception.code, 2)
            resolve.assert_not_called()
