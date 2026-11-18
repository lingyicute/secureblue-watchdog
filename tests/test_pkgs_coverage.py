"""A flat package export must not hide a partial parse."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_sbwatch import S, pkg


class TestPackageExportCoverage(unittest.TestCase):
    def test_export_keeps_parse_diagnostics_and_warns_on_stderr(self):
        table = S.PackageTable({"dnf5": pkg("dnf5", "5.4.8.0-2.fc45")})
        table.fields_skipped = 1
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "packages.json"
            err = io.StringIO()
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", return_value={"digest": "sha256:" + "a" * 64, "annotations": {}}), \
                    patch.object(S, "load_pkglist", return_value=table), contextlib.redirect_stderr(err):
                S.main(["pkgs", "latest", "--json", str(target)])
            self.assertIn("incomplete RPM inventory", err.getvalue())
            data = json.loads(target.read_text())
            self.assertFalse(data["coverage"]["rpmdb_complete"])
            self.assertIn("dnf5", data["packages"])
