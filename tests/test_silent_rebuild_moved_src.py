"""A source chunk changed because a subpackage moved out of it is no silent rebuild."""
import unittest

from test_sbwatch import S, pkg


class TestSilentRebuildMovedSrc(unittest.TestCase):
    def test_old_source_of_migrated_binary_is_not_called_silently_rebuilt(self):
        old_sub = pkg("foo-tool", "1.0-1.fc45", src="oldsrc")
        new_sub = pkg("foo-tool", "1.1-1.fc45", src="newsrc")
        diff = S.pkg_diff({"foo-tool": old_sub, "oldsrc": pkg("oldsrc", "1.0-1.fc45")},
                          {"foo-tool": new_sub, "oldsrc": pkg("oldsrc", "1.0-1.fc45")})
        ldiff = {"changed_chunks": [
            {"components": ["rpm/oldsrc"], "size": 4096, "stability": 0.0},
            {"components": ["rpm/newsrc"], "size": 2048, "stability": 0.0},
        ]}
        xc = S.crosscheck_chunks(ldiff, diff, {"foo-tool": "newsrc", "oldsrc": "oldsrc"})
        self.assertEqual(xc["silent_rebuilds"], [])


if __name__ == "__main__":
    unittest.main()
