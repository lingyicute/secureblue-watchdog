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

    def test_manual_baseline_uses_a_temporary_state_outside_the_cache(self):
        step = WORKFLOW.split("id: check\n", 1)[1].split("run: |\n", 1)[1]
        script = textwrap.dedent(step.split("\n      - name:", 1)[0])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cosign.pub").touch()
            capture = root / "args"
            python = root / "python3"
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n')
            python.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "RUNNER_TEMP": tmp, "CAPTURE": str(capture),
                   "GITHUB_OUTPUT": str(root / "output"),
                   "SB_IMAGE": "secureblue/silverblue-main-hardened", "SB_ARCH": "amd64",
                   "FAIL_ON_SECURITY": "false", "SB_FORCE": "false"}

            def watch(from_tag):
                subprocess.run(["bash", "-c", script], cwd=tmp, check=True,
                               env={**env, "SB_FROM": from_tag}, capture_output=True)
                return capture.read_text().splitlines()

            self.assertNotIn("--state", watch(""))
            manual = watch("20261122")
            self.assertEqual(manual[manual.index("--a") + 1], "20261122")
            state = Path(manual[manual.index("--state") + 1])
            self.assertEqual(state.parent.parent, root)
            self.assertTrue(state.parent.name.startswith("sbwatch-comparison."))
            self.assertEqual(state.name, "state.json")

    def test_summary_history_is_only_published_after_required_verification(self):
        step = WORKFLOW.split("- name: Append build history", 1)[1].split("run: |\n", 1)[1]
        script = textwrap.dedent(step.split("\n\n", 1)[0])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = root / "summary"
            capture = root / "args"
            python = root / "python3"
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n'
                              'echo history-row\nexit "$STATUS"\n')
            python.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "CAPTURE": str(capture), "GITHUB_STEP_SUMMARY": str(summary),
                   "SB_IMAGE": "example/image", "SB_ARCH": "arm64", "WATCHED_INDEX": "sha256:example"}
            for rc in ("0", "1"):
                with self.subTest(status=rc):
                    summary.write_text("")
                    subprocess.run(["bash", "-e", "-c", script], cwd=tmp, check=True,
                                   env={**env, "STATUS": rc}, capture_output=True)
                    args = capture.read_text().splitlines()
                    self.assertIn("--require-cosign", args)
                    self.assertEqual(args[args.index("--cosign-pub") + 1], "cosign.pub")
                    self.assertEqual(args[args.index("--at-digest") + 1], env["WATCHED_INDEX"])
                    body = summary.read_text()
                    self.assertEqual("    history-row" in body, rc == "0")
                    self.assertEqual("Verified history unavailable" in body, rc != "0")
