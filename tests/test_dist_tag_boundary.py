"""Fedora dist tag extraction ignores git hashes and non-ASCII digits."""
import unittest

from test_sbwatch import S, pkg


class TestDistTagBoundary(unittest.TestCase):
    def test_git_hash_prefix_is_not_mistaken_for_fedora_dist_tag(self):
        self.assertEqual(S._dist_tag("1.20261102.fc1234a.fc45"), ".fc45")
        self.assertEqual(S._dist_tag("2.fc45.1"), ".fc45")
        self.assertEqual(S._dist_tag("1.fc４５"), "")
        pkgs = {"foo": pkg("foo", "1.0-1.20261102.fc1234a.fc45")}
        self.assertEqual(S.fedora_release(pkgs), "F45")


if __name__ == "__main__":
    unittest.main()
