"""A partial package table cannot establish no-change or a complete notification."""
import types
import unittest
from unittest.mock import patch
from test_sbwatch import S, pkg


class TestIncompleteRpmdbVerdict(unittest.TestCase):
    def analyse(self, rejected=0, fields=0, collision=False, empty=False):
        pa = S.PackageTable({} if empty else {"bash": pkg("bash", "5.3-1.fc45")})
        pb = S.PackageTable(pa)
        pa.headers_rejected, pa.fields_skipped = rejected, fields
        if collision:
            pa.collisions = [{"name": "bash", "shadowed_arch": "i686", "shadowed_evr": "5.2-1.fc45"}]
        a = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        b = dict(a, ref="b", digest="sha256:" + "b" * 64)
        args = types.SimpleNamespace(image="x/y", arch="amd64", exact=1, keep_order=True,
                                     no_bodhi=True, max_bodhi=0, cache_dir="unused", audit=False)
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "load_pkglist", side_effect=[pa, pb]):
            return S.do_diff(args, "a", "b", images=(a, b))

    def test_partial_tables_never_establish_clean_verdicts(self):
        for reason in ({"rejected": 1}, {"fields": 1}, {"collision": True}, {"empty": True}):
            with self.subTest(reason=reason):
                result = self.analyse(**reason)
                verdict = result["verdict"]
                self.assertEqual(verdict["level"], "unknown")
                self.assertFalse(verdict["package_data_complete"])
                self.assertEqual(verdict["secureblue_notification"]["level"], "unknown")
                md = S.render_markdown("test", result["a"], result["b"], result["diff"],
                                       result["layers"], verdict, result["notes"])
                self.assertNotIn("Every package in both images has the same NEVRA", md)
                self.assertNotIn("no package changed in the rpmdb", verdict["headline"])

    def test_complete_table_keeps_existing_no_change_result(self):
        self.assertEqual(self.analyse()["verdict"]["level"], "no-change")


if __name__ == "__main__":
    unittest.main()
