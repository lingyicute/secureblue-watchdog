"""Cache files are written through the one-pass JSON encoder."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestCacheWrite(unittest.TestCase):
    def test_the_streaming_encoder_is_not_used(self):
        # json.dump() never takes the C encoder: it iterates the document in Python
        doc = {"packages": {"bash": {"evr": "5.3-1.fc45", "changelog": ["修复 CVE"]}}, "n": 1}
        with tempfile.TemporaryDirectory() as d, \
                patch.object(S.json, "dump", side_effect=AssertionError("slow path")):
            path = os.path.join(d, "pkglist.json")
            S._atomic_write_json(path, doc)
            with open(path) as fh:
                self.assertEqual(json.loads(fh.read()), doc)
            self.assertEqual(os.listdir(d), ["pkglist.json"])


if __name__ == "__main__":
    unittest.main()
