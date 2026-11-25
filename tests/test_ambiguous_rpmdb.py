"""Do not infer database identity by sorting competing OCI layers by size."""
import unittest
from test_sbwatch import S


class TestAmbiguousRpmdb(unittest.TestCase):
    # Layer digests from the Nov 14 and Nov 17 F45 platform manifests.
    def setUp(self):
        self.a, self.b = [dict(digest="sha256:" + d, components=["bigfiles/rpmdb.sqlite"], size=i)
                          for i, d in enumerate((
                              "4c886d7e2686e413827457fdadf833d4773db98946379cd3d484a6584570dff3",
                              "a0587488e241659aa3de3ac7331de4be1a4d123228dec017d86a17d68ef1b289"), 1)]

    def test_distinct_candidates_cannot_enable_fast_path(self):
        for layers in ([self.a, self.b], [self.b, self.a]):
            self.assertIsNone(S.rpmdb_chunk({"layers": layers}))
            with self.assertRaisesRegex(SystemExit, "unambiguous"):
                S.package_list(None, {"layers": layers})

    def test_repeated_identical_blob_is_unambiguous(self):
        self.assertEqual(S.rpmdb_chunk({"layers": [self.a, dict(self.a)]}), self.a)

    def test_load_pkglist_deduplicates_repeated_layer_digests_in_avoided_bytes(self):
        import contextlib
        import io
        import tempfile
        from unittest.mock import patch

        rpmdb_layer = dict(self.a, size=10 * 1024 * 1024)
        app_layer = {"digest": "sha256:" + "b" * 64, "components": ["rpm/bash"],
                     "size": 20 * 1024 * 1024}
        img = {"digest": "sha256:" + "c" * 64,
               "layers": [rpmdb_layer, dict(rpmdb_layer), app_layer, dict(app_layer)]}
        notes = []
        with tempfile.TemporaryDirectory() as cache, \
                patch.object(S, "package_list", return_value=S.PackageTable()), \
                contextlib.redirect_stderr(io.StringIO()):
            S.load_pkglist(None, img, "latest", cache, notes)
        self.assertIn("10.0 MiB fetched, 20.0 MiB avoided", notes[0].en)
