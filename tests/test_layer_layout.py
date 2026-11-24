"""Transferring no new blobs can still change the ordered OCI layer stack."""
import unittest

from test_sbwatch import S


def image(*layers):
    return {"layers": [{"digest": d, "components": ["chunkah/unclaimed"], "size": 1024,
                        "stability": 0.0} for d in layers]}


class TestLayerLayout(unittest.TestCase):
    def test_removed_and_reordered_blobs_do_not_count_as_downloads(self):
        diff = S.layer_diff(image("a", "remove", "b"), image("b", "a"))
        self.assertEqual(diff["download_bytes"], 0)
        self.assertEqual(diff["chunks_changed"], 0)
        self.assertEqual(diff["chunks_removed"], 1)
        self.assertEqual(diff["chunks_reused"], 2)
        self.assertTrue(diff["reused_layer_sequence_changed"])
        note = S._layer_layout_note(diff)
        self.assertIn("1 old layer blob", note.en)
        self.assertIn("reused layer order", note.en)
        self.assertIn("不再引用 1 个旧层", note.zh)

    def test_an_added_blob_does_not_reorder_the_reused_subsequence(self):
        diff = S.layer_diff(image("a", "b"), image("a", "new", "b"))
        self.assertEqual(diff["download_bytes"], 1024)
        self.assertEqual(diff["chunks_removed"], 0)
        self.assertFalse(diff["reused_layer_sequence_changed"])
        self.assertIsNone(S._layer_layout_note(diff))

    def test_repeated_descriptors_are_one_blob_but_can_change_the_stack(self):
        diff = S.layer_diff(image("a", "b"), image("a", "b", "b"))
        self.assertEqual(diff["chunks_reused"], 2)
        self.assertEqual(diff["download_bytes"], 0)
        self.assertTrue(diff["reused_layer_sequence_changed"])
