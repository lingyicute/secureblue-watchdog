"""A Packages row whose blob is not binary costs one header, not the whole run."""
import os
import sqlite3
import tempfile
import unittest

from test_sbwatch import S


class _Registry:
    def __init__(self, path):
        self.path = path

    def extract_member(self, chunk, match):
        return self.path


class TestHeaderBlobType(unittest.TestCase):
    def test_a_blob_that_is_not_binary_is_a_rejected_header(self):
        for blob in (None, "kernel", 7, 1.5):
            stats: dict = {}
            self.assertEqual(S.read_header(blob, stats), {})
            self.assertEqual(stats, {"headers_rejected": 1})

    def test_the_package_list_reports_such_rows_instead_of_crashing(self):
        fd, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        con = sqlite3.connect(path)
        con.execute("create table Packages (hnum integer primary key, blob)")
        con.executemany("insert into Packages (blob) values (?)", [(None,), ("text",)])
        con.commit()
        con.close()
        image = {"layers": [{"digest": "sha256:" + "a" * 64, "size": 1, "stability": 0.0,
                             "components": ["bigfiles/rpmdb.sqlite"]}]}
        table = S.package_list(_Registry(path), image)
        self.assertEqual(len(table), 0)
        self.assertEqual(table.headers_rejected, 2)
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
