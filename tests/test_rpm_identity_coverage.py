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
