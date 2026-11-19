"""Manifest-only command output must label the inherited Fedora kernel."""
import contextlib
import io
import unittest
from unittest.mock import patch
from test_sbwatch import S


class TestCliBaseKernel(unittest.TestCase):
    def test_layer_and_tag_output_do_not_claim_an_installed_kernel(self):
        image = {"ref": "latest", "digest": "sha256:" + "a" * 64, "layers": [],
                 "annotations": {"ostree.linux": "7.3.3-300.fc45.x86_64"}}
        for argv in (["tags", "--days", "0"], ["layers", "a", "b"]):
            text = io.StringIO()
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", return_value=image), contextlib.redirect_stdout(text):
                self.assertEqual(S.main(argv), 0)
            self.assertIn("Fedora base kernel 基础内核 (ostree.linux)", text.getvalue())
