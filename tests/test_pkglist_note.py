"""The package-list note states the sizes of the image it is about."""
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestPkglistNote(unittest.TestCase):
    def test_note_reports_this_images_chunk_and_total(self):
        img = {"digest": "sha256:" + "b" * 64, "layers": [
            {"digest": "sha256:1", "size": 10 * 1024 ** 2, "stability": 0.0,
             "components": ["bigfiles/rpmdb.sqlite"]},
            {"digest": "sha256:2", "size": 2 * 1024 ** 3, "stability": 0.0,
             "components": ["rpm/kernel"]}]}
        notes = []
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(S, "package_list", return_value=S.PackageTable()), \
                contextlib.redirect_stderr(io.StringIO()):
            S.load_pkglist(None, img, "latest", directory, notes)
        self.assertIn("(10.0 MiB fetched, 2.0 GiB avoided)", notes[-1].en)
        self.assertIn("（仅下载 10.0 MiB，避免 2.0 GiB）", notes[-1].zh)
        self.assertNotIn("33 MB", notes[-1])


if __name__ == "__main__":
    unittest.main()
