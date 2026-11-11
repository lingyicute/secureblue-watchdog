"""`check --prune-days` drops a Bodhi answer as soon as it is past its TTL."""
import os
import tempfile
import time
import unittest

from test_sbwatch import S


def _files(directory, entries):
    for name, mtime in entries:
        path = os.path.join(directory, name)
        with open(path, "w") as fh:
            fh.write("{}")
        os.utime(path, (mtime, mtime))


class TestBodhiCachePrune(unittest.TestCase):
    def test_a_dead_bodhi_answer_goes_a_package_list_of_that_age_stays(self):
        stale, fresh = time.time() - S.BODHI_TTL - 60, time.time() - S.BODHI_TTL + 600
        with tempfile.TemporaryDirectory() as directory:
            _files(directory, [("bodhi-kernel_F45.json", stale), ("bodhi-curl_F45.json", fresh),
                               ("pkglist-sha256aaa.json", stale)])
            self.assertEqual(S.prune_cache(directory, [], 14), 1)
            self.assertEqual(sorted(os.listdir(directory)),
                             ["bodhi-curl_F45.json", "pkglist-sha256aaa.json"])

    def test_zero_days_still_keeps_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            _files(directory, [("bodhi-kernel_F45.json", time.time() - 30 * 86400)])
            self.assertEqual(S.prune_cache(directory, [], 0), 0)
            self.assertEqual(os.listdir(directory), ["bodhi-kernel_F45.json"])

    def test_the_lookup_refetches_at_the_same_age(self):
        self.assertEqual(S.Bodhi().ttl, S.BODHI_TTL)


if __name__ == "__main__":
    unittest.main()
