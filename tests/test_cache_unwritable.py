"""A cache that cannot be written costs a refetch, never the analysis."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg

IMAGE = {"digest": "sha256:" + "a" * 64, "layers": []}


def _blocked(directory):
    """A path where the cache directory should be, taken by a regular file."""
    path = os.path.join(directory, "cache")
    Path(path).write_text("not a directory")
    return path


def _bodhi_answer():
    return io.BytesIO(json.dumps({"updates": [], "total": 0}).encode())


class TestUnwritableCache(unittest.TestCase):
    def _load(self, cache_dir):
        table = S.PackageTable({"bash": pkg("bash", "5.3-1.fc45")})
        with patch.object(S, "package_list", return_value=table), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            got = S.load_pkglist(None, IMAGE, "latest", cache_dir, [])
        return got, err.getvalue()

    def test_package_list_survives_a_cache_directory_that_cannot_exist(self):
        with tempfile.TemporaryDirectory() as d:
            got, err = self._load(_blocked(d))
        self.assertEqual(list(got), ["bash"])
        self.assertIn("cannot use the cache directory", err)

    def test_package_list_survives_a_cache_file_that_cannot_be_written(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(S, "_atomic_write_json", side_effect=OSError(28, "No space left")):
            got, err = self._load(d)
        self.assertEqual(list(got), ["bash"])
        self.assertIn("cannot write the package list cache", err)

    def test_bodhi_answers_without_a_usable_cache_directory(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(S.urllib.request, "urlopen", return_value=_bodhi_answer()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            bodhi = S.Bodhi(cache_dir=_blocked(d), sleep=0)
            self.assertEqual(bodhi.updates_for_src("curl", "F45"), [])
        self.assertEqual((bodhi.failed, bodhi.cache_dir), (0, None))
        self.assertIn("cannot use the Bodhi cache directory", err.getvalue())

    def test_bodhi_answers_when_its_cache_file_cannot_be_written(self):
        with tempfile.TemporaryDirectory() as d, \
                patch.object(S.urllib.request, "urlopen", return_value=_bodhi_answer()), \
                patch.object(S, "_atomic_write_json", side_effect=OSError(30, "Read-only")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            bodhi = S.Bodhi(cache_dir=d, sleep=0)
            self.assertEqual(bodhi.updates_for_src("curl", "F45"), [])
        self.assertEqual(bodhi.failed, 0)
        self.assertIn("cannot write the Bodhi cache", err.getvalue())


if __name__ == "__main__":
    unittest.main()
