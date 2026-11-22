"""RPM inventories are stored headers, not executable SQLite expressions."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_sbwatch import S, rpm_header


class TestRpmdbGeneratedColumns(unittest.TestCase):
    def test_generated_columns_are_rejected_before_reading_headers(self):
        for storage in ("VIRTUAL", "STORED"):
            with self.subTest(storage=storage), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "rpmdb.sqlite"
                with sqlite3.connect(path) as con:
                    con.execute("CREATE TABLE Packages(seed INTEGER, blob BLOB "
                                f"GENERATED ALWAYS AS (zeroblob(seed)) {storage})")
                    con.execute("INSERT INTO Packages(seed) VALUES (4096)")
                reg = Mock()
                reg.extract_member.return_value = str(path)
                image = {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]}
                with patch.object(S, "read_header") as read:
                    with self.assertRaisesRegex(SystemExit, "generated columns"):
                        S.package_list(reg, image)
                    read.assert_not_called()
                self.assertFalse(path.exists())

    def test_a_generated_unselected_column_is_rejected_too(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rpmdb.sqlite"
            with sqlite3.connect(path) as con:
                con.execute("CREATE TABLE Packages(blob BLOB, extra TEXT "
                            "GENERATED ALWAYS AS (hex(blob)) VIRTUAL)")
            reg = Mock()
            reg.extract_member.return_value = str(path)
            with self.assertRaisesRegex(SystemExit, "generated columns"):
                S.package_list(reg, {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]})
            self.assertFalse(path.exists())

    def test_upstream_rpm_sqlite_schema_remains_supported(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rpmdb.sqlite"
            header = rpm_header([(1000, 6, b"curl\0"), (1001, 6, b"8.21.0\0"),
                                 (1002, 6, b"9.fc45\0"), (1022, 6, b"x86_64\0")])
            with sqlite3.connect(path) as con:
                con.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY AUTOINCREMENT, "
                            "blob BLOB NOT NULL)")
                con.execute("INSERT INTO Packages(blob) VALUES (?)", (header,))
            reg = Mock()
            reg.extract_member.return_value = str(path)
            table = S.package_list(reg, {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]})
            self.assertEqual(table["curl"]["evr"], "8.21.0-9.fc45")
            self.assertTrue(S.package_coverage(table)["rpmdb_complete"])
            self.assertFalse(path.exists())

    def test_caches_from_before_schema_validation_are_refetched(self):
        self.assertIsNone(S._pkglist_from_cache({"cache_version": 6, "packages": {},
                                               "collisions": [], "headers_rejected": 0,
                                               "fields_skipped": 0}))
