"""fedora_release prefers Fedora packages and breaks ties toward the newer release."""
import unittest

from test_sbwatch import S, pkg


class TestFedoraReleaseSelection(unittest.TestCase):
    def test_third_party_dist_tags_do_not_outvote_fedora_packages(self):
        pkgs = {
            "a": dict(pkg("a", "1.0-1.fc44"), vendor="negativo17.org"),
            "b": dict(pkg("b", "1.0-1.fc44"), vendor="negativo17.org"),
            "c": dict(pkg("c", "1.0-1.fc45"), vendor="Fedora Project"),
        }
        self.assertEqual(S.fedora_release(pkgs), "F45")

    def test_equal_count_tie_picks_higher_release_regardless_of_order(self):
        p1 = {"a": pkg("a", "1.0-1.fc44"), "b": pkg("b", "1.0-1.fc45")}
        p2 = {"b": pkg("b", "1.0-1.fc45"), "a": pkg("a", "1.0-1.fc44")}
        self.assertEqual(S.fedora_release(p1), "F45")
        self.assertEqual(S.fedora_release(p2), "F45")


if __name__ == "__main__":
    unittest.main()
