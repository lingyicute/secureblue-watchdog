"""A chunk that changed at an unchanged version is not reported as a rebuild."""
import unittest

from test_sbwatch import S, pkg


def layer(digit, size):
    # the live glibc chunks of 45.20261114.0 and 45.20261116.0: their 1443 members
    # were identical except etc/ld.so.cache (76683 -> 76735 bytes)
    return {"digest": "sha256:" + digit * 64, "size": size, "components": ["rpm/glibc"],
            "stability": 0.45}


def image(n):
    return {"ref": f"r{n}", "digest": "sha256:" + str(n) * 64, "annotations": {}, "created": ""}


class TestSameVersionChunkWording(unittest.TestCase):
    def test_no_rebuild_is_claimed(self):
        glibc = pkg("glibc", "2.44-2.fc45")
        diff = S.pkg_diff({"glibc": glibc}, {"glibc": dict(glibc)})
        layers = S.layer_diff({"layers": [layer("a", 85450396)]},
                              {"layers": [layer("b", 85450390)]})
        xc = S.crosscheck_chunks(layers, diff)
        verdict = S.verdict_of(diff, layers, {}, xc)
        self.assertEqual(verdict["level"], "consider")
        self.assertIn("chunk changed at an identical version: glibc", verdict["headline"])
        self.assertIn("版本相同但 chunk 变化：glibc", verdict["headline_zh"])
        self.assertEqual(verdict["level_basis"],
                         "the chunks of security-relevant packages changed at the same version")
        md = S.render_markdown("t", image(1), image(2), diff, layers, verdict, [], xc)
        self.assertIn("## Same version, changed chunk (1)", md)
        self.assertIn("## 版本相同但 chunk 变化（1）", md)
        self.assertIn("`etc/ld.so.cache`", md)
        for claim in ("rebuilt (identical version)", "Rebuilt with the", "被重建", "重建（版本相同）"):
            self.assertNotIn(claim, verdict["headline"] + verdict["headline_zh"] + md)


if __name__ == "__main__":
    unittest.main()
