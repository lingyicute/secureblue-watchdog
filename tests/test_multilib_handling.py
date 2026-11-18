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

    def test_collision_present_only_in_older_image_is_still_disclosed(self):
        pa = S.PackageTable({"glibc": pkg("glibc", "2.41-1.fc45")})
        pa.collisions = [{"name": "glibc", "kept_arch": "x86_64", "kept_evr": "2.41-1.fc45",
                          "shadowed_arch": "i686", "shadowed_evr": "2.40-1.fc45"}]
        pb = S.PackageTable({"glibc": pkg("glibc", "2.41-2.fc45")})
        img = lambda d: {"ref": d, "digest": "sha256:" + d * 64, "created": "",
                         "annotations": {}, "layers": []}
        args = types.SimpleNamespace(exact=1, keep_order=True, no_bodhi=True, max_bodhi=0,
                                     audit=False, cache_dir="/tmp", cosign_pub=None,
                                     require_cosign=False)

        class _Reg:
            def _token(self):
                return None

        with patch.object(S, "load_pkglist", side_effect=[pa, pb]):
            res = S.do_diff(args, "a", "b", images=(img("a"), img("b")), reg=_Reg())
        self.assertTrue(any("glibc.i686" in str(n) for n in res["notes"]))


    def test_collision_with_differing_epochs_records_both_epochs(self):
        t = S.PackageTable()
        S.table_put(t, dict(pkg("foo", "1.0-1.fc45", epoch="0"), arch="x86_64"))
        S.table_put(t, dict(pkg("foo", "1.0-1.fc45", epoch="1"), arch="i686"))
        self.assertEqual(t.collisions[0]["kept_evr"], "1:1.0-1.fc45")
        self.assertEqual(t.collisions[0]["shadowed_evr"], "0:1.0-1.fc45")

    def test_same_architecture_multiple_builds_also_make_inventory_partial(self):
        table = S.PackageTable()
        S.table_put(table, pkg("kernel", "7.3.3-1.fc45"))
        S.table_put(table, pkg("kernel", "7.3.4-1.fc45"))
        self.assertEqual(table["kernel"]["version"], "7.3.4")
        self.assertEqual(len(table.collisions), 1)
        self.assertFalse(S.package_coverage(table)["rpmdb_complete"])

    def test_same_version_with_different_arch_is_not_the_same_nevra(self):
        old = dict(pkg("glibc", "2.42-1.fc45"), arch="i686")
        new = dict(old, arch="x86_64")
        d = S.pkg_diff({"glibc": old}, {"glibc": new})
        self.assertEqual(d["changed"][0]["dir"], "arch-change")
        g, = S.group_by_src(d["changed"])
        self.assertEqual((g["old_evr"], g["new_evr"]), ("2.42-1.fc45.i686", "2.42-1.fc45.x86_64"))


if __name__ == "__main__":
    unittest.main()
