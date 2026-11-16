"""Source RPM parsing extracts the source name even for non-digit versions."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from test_sbwatch import S, rpm_header


class TestSourceRpmName(unittest.TestCase):
    def test_alpha_prefixed_version_still_yields_the_source_name(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "rpmdb.sqlite"
            con = sqlite3.connect(db)
            con.execute("create table Packages (blob BLOB)")
            for nm, ver, srpm in (
                ("foo-libs", "r128", "foo-r128-1.fc45.src.rpm"),
                ("polkit-qt6-1", "0.200.0", "polkit-qt-1-0.200.0-1.fc45.src.rpm"),
            ):
                blob = rpm_header([(1000, 6, nm.encode() + b"\0"),
                                   (1001, 6, ver.encode() + b"\0"),
                                   (1002, 6, b"1.fc45\0"),
                                   (1044, 6, srpm.encode() + b"\0")])
                con.execute("insert into Packages values (?)", (blob,))
            con.commit()
            con.close()

            class _Reg:
                def extract_member(self, layer, match):
                    return str(db)

            img = {"layers": [{"digest": "sha256:" + "b" * 64, "size": 1,
                               "components": ["bigfiles/rpmdb.sqlite"]}]}
            pkgs = S.package_list(_Reg(), img)
            self.assertEqual(pkgs["foo-libs"]["src"], "foo")
            self.assertEqual(pkgs["polkit-qt6-1"]["src"], "polkit-qt-1")


if __name__ == "__main__":
    unittest.main()
