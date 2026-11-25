"""Missing image annotations render as '?' instead of literal None."""
import contextlib
import io
import types
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestMissingAnnotationsDisplay(unittest.TestCase):
    def _img(self, ref, ann=None):
        return {
            "ref": ref,
            "digest": "sha256:" + "1" * 64,
            "index_digest": "sha256:" + "2" * 64,
            "annotations": {} if ann is None else ann,
            "layers": [],
            "created": "",
        }

    def test_tags_and_layers_do_not_print_none_for_missing_annotations(self):
        reg = types.SimpleNamespace(_token=lambda: None, host="ghcr.io", repo="secureblue/sc")
        img_a, img_b = self._img("a"), self._img("b")
        out_tags = io.StringIO()
        with patch.object(S, "_registry", return_value=reg), \
                patch.object(S, "resolve", return_value=img_a), \
                patch.object(S, "maybe_verify_resolved"), \
                contextlib.redirect_stdout(out_tags):
            S.cmd_tags(types.SimpleNamespace(to="latest", days=0))
        self.assertNotIn("None", out_tags.getvalue())
        self.assertIn("version 版本: ?", out_tags.getvalue())
        self.assertIn("(ostree.linux): ?", out_tags.getvalue())

        out_layers = io.StringIO()
        with patch.object(S, "_registry", return_value=reg), \
                patch.object(S, "resolve", side_effect=[img_a, img_b]), \
                patch.object(S, "maybe_verify_resolved"), \
                contextlib.redirect_stdout(out_layers):
            S.cmd_layers(types.SimpleNamespace(
                image="secureblue/sc", a="a", b="b", keep_order=True, json=None))
        self.assertNotIn("None", out_layers.getvalue())
        self.assertIn("version 版本: ? -> ?", out_layers.getvalue())
        self.assertIn("(ostree.linux):  ? -> ?", out_layers.getvalue())

    def test_markdown_metadata_table_replaces_null_annotations_with_question_mark(self):
        img = self._img("a", {"org.opencontainers.image.version": None, "ostree.linux": None})
        diff = {"changed": [], "added": [], "removed": [], "count_a": 1, "count_b": 1}
        ld = S.layer_diff(img, img)
        v = S.verdict_of(diff, ld, {})
        md = S.render_markdown("s", img, img, diff, ld, v, [])
        self.assertNotIn("| None |", md)
        self.assertIn("| image version | ? | ? |", md)
        self.assertIn("| kernel (`ostree.linux` annotation, from the Fedora base) | ? | ? |", md)


if __name__ == "__main__":
    unittest.main()
