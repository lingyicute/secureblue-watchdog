"""BACKLOG_POOL contains Fedora source packages, never secureblue-only ones."""
import unittest

from test_sbwatch import S


class TestBacklogPoolSources(unittest.TestCase):
    def test_trivalent_is_important_but_not_audited_against_bodhi(self):
        self.assertIn("trivalent", S.IMPORTANT_SRC)
        self.assertNotIn("trivalent", S.BACKLOG_POOL)


if __name__ == "__main__":
    unittest.main()
