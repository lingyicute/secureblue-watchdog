"""A no-change verdict must name every changed chunk of unowned files, not only
chunkah/unclaimed: secureblue's own configuration also ships as bigfiles/*."""
import unittest

from test_sbwatch import S


def chunk(component, size):
    return {"components": [component], "size": size, "stability": 0.0}


def verdict(*chunks):
    diff = S.pkg_diff({}, {})
    ldiff = {"download_bytes": sum(c["size"] for c in chunks), "changed_chunks": list(chunks)}
    return S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff))


class TestUnownedBigfilesNote(unittest.TestCase):
    def test_secureblue_config_in_a_bigfiles_chunk_is_disclosed(self):
        # component and size as in the live 45.20261117.0 manifest
        v = verdict(chunk("bigfiles/usr/share/secureblue/etc/trivalent/filter/"
                          "trivalent-blocklist", 4931496))
        self.assertEqual(v["level"], "no-change")
        self.assertIn("Not inspected: 4.7 MiB", v["headline"])
        self.assertIn("未检查", v["headline_zh"])

    def test_the_rpmdb_chunk_alone_is_not_unowned_content(self):
        v = verdict(chunk("bigfiles/rpmdb.sqlite", 33504432))
        self.assertEqual(v["level"], "no-change")
        self.assertNotIn("Not inspected", v["headline"])

    def test_a_regenerated_initramfs_alone_adds_nothing(self):
        v = verdict(chunk("bigfiles/initramfs.img", 247026065))
        self.assertNotIn("Not inspected", v["headline"])

    def test_unclaimed_still_counts(self):
        v = verdict(chunk("chunkah/unclaimed", 9962319))
        self.assertIn("Not inspected: 9.5 MiB", v["headline"])


if __name__ == "__main__":
    unittest.main()
