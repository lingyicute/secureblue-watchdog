"""A portable diff records the images actually compared, not mutable inputs alone."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_sbwatch import S, pkg
from test_check_state import _image


class TestDiffProvenance(unittest.TestCase):
    def test_export_follows_orientation(self):
        old, new = _image(1), _image(2)
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'diff.json'
            with patch.object(S.Registry, '_token', return_value=None), \
                    patch.object(S, 'resolve', side_effect=lambda reg, ref, **k:
                        dict(new if ref == 'latest' else old, ref=ref)), \
                    contextlib.redirect_stdout(io.StringIO()):
                S.main(['diff', 'latest', 'previous', '--exact', '0', '--json-out', str(out)])
            payload = json.loads(out.read_text())
        self.assertEqual((payload['from'], payload['to']), ('previous', 'latest'))
        self.assertEqual((payload['from_digest'], payload['digest']), (old['digest'], new['digest']))


class TestSharedComparisonExport(unittest.TestCase):
    def test_package_set_architecture_and_snapshot_details_survive_export(self):
        res = {"a": {"ref": "old", "digest": "old-platform", "index_digest": "old-index"},
               "b": {"ref": "new", "digest": "new-platform", "index_digest": "new-index"},
               "diff": {"added": ["added"], "removed": ["removed"],
                        "rpmdb_issues": {"fields_skipped": 2}, "changed": [
                            {"name": "binary", "src": "source", "dir": "arch-change",
                             "old": {"evr": "1-1", "arch": "i686"},
                             "new": {"evr": "1-1", "arch": "x86_64"}}]},
               "verdict": {"level": "unknown"}, "layers": {"download_bytes": 123}}
        payload = S._comparison_json(res)
        self.assertEqual((payload["from_digest"], payload["from_index_digest"]),
                         ("old-platform", "old-index"))
        self.assertEqual((payload["digest"], payload["index_digest"]), ("new-platform", "new-index"))
        self.assertEqual((payload["added"], payload["removed"]), (["added"], ["removed"]))
        self.assertEqual(payload["rpmdb_issues"], {"fields_skipped": 2})
        row, = payload["changed"]
        self.assertEqual((row["old_arch"], row["new_arch"], row["dir"]), ("i686", "x86_64", "arch-change"))

    def test_exact_identity_preserves_unchanged_epochs_and_package_set_records(self):
        # android-tools has Epoch 1 on both sides of the 20261122 -> 20261123 diff.
        pa = {"android-tools": pkg("android-tools", "37.0.0p1-1.fc45", epoch="1"),
              "rar": pkg("rar", "7.20-1")}
        pb = {"android-tools": pkg("android-tools", "37.0.0p1-2.fc45", epoch="1"),
              "unar": pkg("unar", "1.10.8-1.fc45")}
        res = {"a": {"digest": "old"}, "b": {"digest": "new"}, "diff": S.pkg_diff(pa, pb),
               "verdict": {"level": "consider"}, "layers": {"download_bytes": 0}}
        data = S._comparison_json(res)
        row, = data["changed"]
        self.assertEqual((row["old"], row["new"]), ("37.0.0p1-1.fc45", "37.0.0p1-2.fc45"))
        self.assertEqual((row["old_nevra"]["epoch"], row["new_nevra"]["epoch"]), ("1", "1"))
        self.assertEqual(row["new_nevra"]["release"], "2.fc45")
        self.assertEqual(data["added"], ["unar"])
        self.assertEqual(data["added_nevra"][0]["version"], "1.10.8")
        self.assertEqual(data["removed"], ["rar"])
        self.assertEqual(data["removed_nevra"][0]["name"], "rar")
