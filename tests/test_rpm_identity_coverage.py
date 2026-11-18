"""Invalid RPM metadata is a coverage gap, not a clean empty field."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_sbwatch import S, rpm_header


class TestRpmIdentityCoverage(unittest.TestCase):
    def test_non_text_vendor_is_counted(self):
        stats = {}
        header = rpm_header([(1011, 4, b"\x00\x00\x00\x01")])
        self.assertNotIn("vendor", S.read_header(header, stats))
        self.assertEqual(stats["fields_skipped"], 1)

    def test_wrong_scalar_type_and_undecodable_identifier_are_disclosed(self):
        for field in ((1000, 8, b"bash\0"), (1000, 6, b"bad\xff\0")):
            with self.subTest(field=field):
                stats = {}
                self.assertNotIn("name", S.read_header(rpm_header([field]), stats))
                self.assertEqual(stats["fields_skipped"], 1)

    def test_trailing_store_truncation_rejects_the_header(self):
        stats = {}
        header = rpm_header([(1000, 6, b"bash\0"), (1002, 6, b"1.fc45\0")])
        self.assertFalse(S.read_header(header[:-1], stats))
        self.assertEqual(stats["headers_rejected"], 1)

    def test_mismatched_changelog_array_lengths_make_inventory_incomplete(self):
        tags = [(1000, 6, b"bash\0"), (1001, 6, b"5.3\0"),
                (1002, 6, b"1.fc45\0"), (1022, 6, b"x86_64\0"),
                (1082, 8, b"Fix a bug\0")]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rpmdb.sqlite"
            con = sqlite3.connect(path)
            con.execute("create table Packages(blob blob)")
            con.execute("insert into Packages values (?)", (rpm_header(tags),))
            con.commit()
            con.close()
            reg = Mock()
            reg.extract_member.return_value = str(path)
            table = S.package_list(reg, {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]})
        self.assertIn("bash", table)
        self.assertFalse(S.package_coverage(table)["rpmdb_complete"])

    def test_incomplete_identity_is_not_a_package(self):
        identity = [(1000, 6, b"bash\0"), (1001, 6, b"5.3\0"),
                    (1002, 6, b"1.fc45\0"), (1022, 6, b"x86_64\0")]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rpmdb.sqlite"
            con = sqlite3.connect(path)
            con.execute("create table Packages(blob blob)")
            for omit in (1002, 1022):
                con.execute("insert into Packages values (?)", (
                    rpm_header([x for x in identity if x[0] != omit]),))
            con.execute("insert into Packages values (?)", (
                rpm_header([(1000, 6, b"gpg-pubkey\0")]),))
            con.commit()
            con.close()
            reg = Mock()
            reg.extract_member.return_value = str(path)
            table = S.package_list(reg, {"layers": [{"components": ["rpmdb.sqlite"], "size": 1}]})
        self.assertFalse(table)
        self.assertEqual(table.headers_rejected, 2)
