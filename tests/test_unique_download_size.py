"""The cold-pull and incremental byte counts use unique blob digests."""
import unittest
from test_sbwatch import S
from test_live_20261117 import FIXTURE


class TestUniqueDownloadSize(unittest.TestCase):
    def test_a_repeated_real_layer_downloads_only_once(self):
        layer = FIXTURE["images"]["new"]["glibc_layers"][0]
        target = {"layers": [layer, dict(layer)]}
        result = S.layer_diff({"layers": []}, target)
        self.assertEqual(result["total_size_b"], layer["size"])
        self.assertEqual(result["download_bytes"], layer["size"])
        self.assertEqual(result["download_pct"], 100)
        self.assertEqual(S.layer_diff({"layers": [layer]}, target)["chunks_reused"], 1)
