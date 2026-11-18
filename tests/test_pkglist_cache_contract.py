"""A JSON file bearing the current cache version is not necessarily a package table."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sbwatch as S


class TestPkglistCacheContract(unittest.TestCase):
    def test_current_version_with_broken_entry_is_refetched(self):
        digest = "sha256:" + "a" * 64
        pkg = {"name": "bash", "src": "bash", "arch": "x86_64", "version": "5.3", "release": "1.fc45",
               "evr": "5.3-1.fc45", "nvr": "bash-5.3-1.fc45", "vendor": "Fedora Project",
               "srpm": "bash-5.3-1.fc45", "epoch": "", "changelog": []}
        image = {"digest": digest, "layers": []}
        real = S.PackageTable({"bash": pkg})
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / f"pkglist-{digest.replace(':', '')}.json"
            cache.write_text(json.dumps({"cache_version": S.PKGLIST_CACHE_VERSION,
                                         "packages": {"bash": dict(pkg, changelog=[None])},
                                         "collisions": [], "headers_rejected": 0, "fields_skipped": 0}))
            with patch.object(S, "package_list", return_value=real) as fetch:
                self.assertEqual(S.load_pkglist(None, image, "latest", tmp, []), real)
                self.assertEqual(S.load_pkglist(None, image, "latest", tmp, []), real)
            fetch.assert_called_once()
