"""The live default retains its cache, and other image selectors do not collide."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows/sbwatch.yml").read_text()


class TestWorkflowCacheScope(unittest.TestCase):
    def test_tag_and_repository_with_same_slug_are_distinct(self):
        step = WORKFLOW.split("id: ns\n", 1)[1].split("run: |\n", 1)[1].split("\n\n", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "output"

            def key(image):
                out.touch()
                subprocess.run(["bash", "-e", "-c", textwrap.dedent(step)], check=True,
                               env={**os.environ, "SB_IMAGE": image, "GITHUB_OUTPUT": str(out)})
                return out.read_text().splitlines()[-1]

            self.assertEqual(key("secureblue/silverblue-main-hardened"),
                             "ns=secureblue-silverblue-main-hardened")
            self.assertNotEqual(key("secureblue/silverblue-main-hardened:45"),
                                key("secureblue/silverblue-main-hardened-45"))

    def test_prune_query_and_deletion_both_stay_on_the_current_ref(self):
        self.assertIn("key: prefix, ref: context.ref", WORKFLOW)
        self.assertIn("c.ref === context.ref && c.key.startsWith(prefix)", WORKFLOW)
        self.assertIn("sort: 'created_at', direction: 'desc'", WORKFLOW)
