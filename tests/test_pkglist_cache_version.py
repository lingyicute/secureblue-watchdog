"""Package-list caches predating vendor tracking are refetched."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestPkglistCacheVersion(unittest.TestCase):
    def test_unversioned_cache_is_refetched_and_upgraded(self):
        dig = "sha256:" + "a" * 64
        img = {"digest": dig, "layers": []}
        fresh = S.PackageTable({"ffmpeg": dict(pkg("ffmpeg", "9.0.2-2.fc45", epoch="1"),
                                               vendor="negativo17.org")})
        with tempfile.TemporaryDirectory() as td:
            cf = Path(td) / f"pkglist-{dig.replace(':', '')}.json"
            cf.write_text(json.dumps({"packages": {"ffmpeg": pkg("ffmpeg", "9.0.2-2.fc45")},
                                      "pad": "x" * 12_000}))
            notes = []
            with patch.object(S, "package_list", return_value=fresh) as fetch, \
                    contextlib.redirect_stderr(io.StringIO()):
                got = S.load_pkglist(None, img, "latest", td, notes)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(got["ffmpeg"]["vendor"], "negativo17.org")
            saved = json.loads(cf.read_text())
            self.assertEqual(saved["cache_version"], S.PKGLIST_CACHE_VERSION)


if __name__ == "__main__":
    unittest.main()
