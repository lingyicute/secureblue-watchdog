"""A run killed mid-write leaves `<cache file>.tmp.<pid>` behind; pruning drops it."""
import os
import tempfile
import time
import unittest

from test_sbwatch import S


def _prune(entries, keep=()):
    with tempfile.TemporaryDirectory() as directory:
        for name, mtime in entries:
            path = os.path.join(directory, name)
            with open(path, "w") as fh:
                fh.write("{}")
            os.utime(path, (mtime, mtime))
        removed = S.prune_cache(directory, list(keep), 14)
        return removed, sorted(os.listdir(directory))


class TestOrphanedTempFilesArePruned(unittest.TestCase):
    def setUp(self):
        self.old = time.time() - S.TMP_FILE_GRACE - 60
        self.fresh = time.time() - 60

    def test_an_abandoned_temp_file_goes_whatever_the_retention(self):
        removed, left = _prune([("pkglist-sha256aaa.json.tmp.4242", self.old),
                                ("bodhi-curl_F45.json.tmp.77", self.old),
                                ("pkglist-sha256bbb.json", self.old)])
        self.assertEqual(removed, 2)
        self.assertEqual(left, ["pkglist-sha256bbb.json"])

    def test_a_temp_file_still_being_written_stays(self):
        removed, left = _prune([("pkglist-sha256aaa.json.tmp.4242", self.fresh)])
        self.assertEqual(removed, 0)
        self.assertEqual(left, ["pkglist-sha256aaa.json.tmp.4242"])

    def test_the_temp_file_of_a_kept_digest_is_no_package_list(self):
        removed, left = _prune([("pkglist-sha256aaa.json.tmp.1", self.old),
                                ("pkglist-sha256aaa.json", self.old)], keep=["sha256:aaa"])
        self.assertEqual(removed, 1)
        self.assertEqual(left, ["pkglist-sha256aaa.json"])

    def test_files_that_are_not_cache_files_stay(self):
        names = ["notes.json.tmp.1", "pkglist-sha256aaa.json.tmp.old", "state.json.tmp.5"]
        removed, left = _prune([(n, self.old) for n in names])
        self.assertEqual(removed, 0)
        self.assertEqual(left, names)


if __name__ == "__main__":
    unittest.main()
