"""Multilib tie-breaking and collision disclosure across both diffed images."""
import types
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestMultilibHandling(unittest.TestCase):
    def test_equal_evr_multilib_winner_does_not_depend_on_insertion_order(self):
        i686 = dict(pkg("glibc", "2.41-1.fc45"), arch="i686")
        x86 = dict(pkg("glibc", "2.41-1.fc45"), arch="x86_64")
        t1, t2 = S.PackageTable(), S.PackageTable()
        S.table_put(t1, i686); S.table_put(t1, x86)
        S.table_put(t2, x86); S.table_put(t2, i686)
        self.assertEqual(t1["glibc"]["arch"], "x86_64")
        self.assertEqual(t2["glibc"]["arch"], "x86_64")
        self.assertEqual(t1.collisions, t2.collisions)


if __name__ == "__main__":
    unittest.main()
