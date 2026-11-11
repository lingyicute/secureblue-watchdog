"""Vendor and License are read from their own rpm header tags."""
import unittest

from test_sbwatch import S, rpm_header


class TestVendorAndLicenseTags(unittest.TestCase):
    # rpmtag.h: RPMTAG_DISTRIBUTION = 1010, RPMTAG_VENDOR = 1011, RPMTAG_LICENSE = 1014
    HEADER = rpm_header([(1000, 6, b"bash\0"), (1010, 6, b"Fedora Linux\0"),
                         (1011, 6, b"Fedora Project\0"), (1014, 6, b"GPL-3.0-or-later\0")])

    def test_each_field_comes_from_its_own_tag(self):
        h = S.read_header(self.HEADER)
        self.assertEqual(h["name"], "bash")
        self.assertEqual(h["vendor"], "Fedora Project")
        self.assertEqual(h["license"], "GPL-3.0-or-later")

    def test_distribution_is_not_listed_as_the_vendor(self):
        self.assertNotIn(1010, S.RPMTAG)
        self.assertEqual((S.RPMTAG[1011], S.RPMTAG[1014]), ("vendor", "license"))


if __name__ == "__main__":
    unittest.main()
