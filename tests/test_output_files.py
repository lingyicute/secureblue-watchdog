"""Output files are written atomically, and into a directory that may not exist yet."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


def _image(ref, created, layers):
    return {"ref": ref, "digest": "sha256:" + ref * 64, "index_digest": "sha256:" + ref * 64,
            "created": created, "annotations": {}, "layers": layers}


def _layer(n, size, component):
    return {"digest": "sha256:" + str(n) * 64, "size": size, "components": [component],
            "stability": 0.0}


OLD = _image("a", "2026-01-01T00:00:00Z", [_layer(1, 100, "rpm/kernel"), _layer(2, 20, "rpm/curl")])
NEW = _image("b", "2026-01-02T00:00:00Z", [_layer(1, 100, "rpm/kernel"), _layer(3, 25, "rpm/curl")])


class TestAtomicWriters(unittest.TestCase):
    def test_missing_directories_are_created(self):
        with tempfile.TemporaryDirectory() as d:
            text = Path(d, "out", "deep", "report.md")
            S._atomic_write_text(str(text), "# 报告\n")
            self.assertEqual(text.read_text(encoding="utf-8"), "# 报告\n")
            data = Path(d, "x", "r.json")
            S._atomic_write_json(str(data), {"a": [1, 2]}, indent=1)
            self.assertEqual(json.loads(data.read_text()), {"a": [1, 2]})
            self.assertIn("\n", data.read_text())            # indent=1: one item per line
            self.assertEqual(os.listdir(data.parent), ["r.json"])

    def test_a_bare_file_name_still_works(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                S._atomic_write_text("r.md", "x")
                S._atomic_write_json("r.json", {})
                self.assertEqual(sorted(os.listdir(".")), ["r.json", "r.md"])
            finally:
                os.chdir(previous)


class TestCommandOutputs(unittest.TestCase):
    def _run(self, argv):
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "resolve",
                             side_effect=lambda reg, ref, light=False: dict({"a": OLD, "b": NEW}[ref])), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return S.main(argv)

    def test_layers_json_goes_into_a_directory_that_does_not_exist(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "no", "such", "layers.json")
            self.assertEqual(self._run(["layers", "a", "b", "--json", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["download_bytes"], 25)
            self.assertEqual(os.listdir(out.parent), ["layers.json"])

    def test_diff_markdown_and_json_out_go_into_missing_directories(self):
        with tempfile.TemporaryDirectory() as d:
            md, js = Path(d, "m", "diff.md"), Path(d, "j", "diff.json")
            rc = self._run(["diff", "a", "b", "--exact", "0", "--markdown", str(md),
                            "--json-out", str(js)])
            self.assertEqual(rc, 0)
            self.assertIn("chunk", md.read_text(encoding="utf-8"))
            data = json.loads(js.read_text())
            self.assertEqual(data["verdict"]["level"], "unknown")
            self.assertEqual(data["download_bytes"], 25)
            self.assertEqual(os.listdir(js.parent), ["diff.json"])


if __name__ == "__main__":
    unittest.main()
