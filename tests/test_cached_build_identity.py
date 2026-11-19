"""Refetch internally inconsistent package identities, even at the current schema."""
import unittest
from test_sbwatch import S
from test_live_20261117 import FIXTURE


class TestCachedBuildIdentity(unittest.TestCase):
    def load(self, **updates):
        p = dict(FIXTURE["images"]["new"]["packages"]["dnf5"], changelog=[])
        p.update(updates)
        return S._pkglist_from_cache(dict(cache_version=S.PKGLIST_CACHE_VERSION,
            packages={"dnf5": p}, collisions=[], headers_rejected=0, fields_skipped=0))

    def test_bad_derived_fields_in_a_real_build(self):
        for change in ({"nvr": "other-1-2"}, {"evr": "5.4.7.0-1.fc45"},
                       {"src": "other"}, {"epoch": "unknown"}):
            with self.subTest(change=change):
                self.assertIsNone(self.load(**change))

    def test_real_package_and_independently_versioned_subpackage_remain_valid(self):
        self.assertIsNotNone(self.load())
        self.assertIsNotNone(self.load(src="different-source", srpm="different-source-8.0-4.fc45"))
