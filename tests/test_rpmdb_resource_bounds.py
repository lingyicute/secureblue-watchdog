"""A small SQLite file must not expand into an unbounded logical inventory."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from test_sbwatch import S, rpm_header


class TestRpmdbResourceBounds(unittest.TestCase):
    def inventory(self, td, rows=1, view=False):
        path = Path(td) / "rpmdb.sqlite"
        with sqlite3.connect(path) as con:
            con.execute("CREATE TABLE data(blob BLOB)" if view else "CREATE TABLE Packages(blob BLOB)")
            for i in range(rows):
                header = rpm_header([(1000, 6, f"pkg{i}\0".encode()), (1001, 6, b"1\0"),
                                     (1002, 6, b"1.fc45\0"), (1022, 6, b"x86_64\0")])
                con.execute("INSERT INTO " + ("data" if view else "Packages") + " VALUES (?)", (header,))
            if view:
                # This could instead be a recursive CTE generating arbitrarily many rows.
                con.execute("CREATE VIEW Packages AS SELECT blob FROM data")
        reg = Mock()
        reg.extract_member.return_value = str(path)
        return reg, path, {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]}

    def test_packages_view_is_rejected_before_evaluation(self):
        with tempfile.TemporaryDirectory() as td:
            reg, path, image = self.inventory(td, view=True)
            with self.assertRaisesRegex(SystemExit, "ordinary table"):
                S.package_list(reg, image)
            self.assertFalse(path.exists())

    def test_row_budget_fails_closed_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as td, patch.object(S, "MAX_RPM_HEADERS", 2, create=True):
            reg, path, image = self.inventory(td, rows=3)
            with self.assertRaisesRegex(SystemExit, "header.*limit"):
                S.package_list(reg, image)
            self.assertFalse(path.exists())

    def test_exactly_at_the_row_budget_is_complete(self):
        with tempfile.TemporaryDirectory() as td, patch.object(S, "MAX_RPM_HEADERS", 2, create=True):
            reg, path, image = self.inventory(td, rows=2)
            packages = S.package_list(reg, image)
            self.assertEqual(len(packages), 2)
            self.assertTrue(S.package_coverage(packages)["rpmdb_complete"])
            self.assertFalse(path.exists())
