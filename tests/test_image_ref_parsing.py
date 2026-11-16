"""Image reference parsing rejects empty digests and handles mixed-case hosts."""
import unittest

from test_sbwatch import S


class TestImageRefParsing(unittest.TestCase):
    def test_trailing_at_is_rejected_instead_of_silently_using_latest(self):
        for bad in ("ns/name@", "ghcr.io/ns/name@", "ghcr.io/ns/name:latest@"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                S.Registry._split(bad)


if __name__ == "__main__":
    unittest.main()
