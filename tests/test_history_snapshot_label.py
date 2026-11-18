"""An anchored history calls the snapshot `--to` only while that tag still points at it."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S

SNAP = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def _run(**tag_lookup):
    img = {"digest": SNAP, "index_digest": SNAP, "annotations": {}}
    row = {"digest": SNAP, "tags": ["latest"], "version": "45.20261116.0",
           "inputhash": None, "kernel": None, "created": "2026-11-17T01:06:51Z",
           "image": img}
    out = io.StringIO()
    with (patch.object(S.Registry, "_token", return_value=None),
          patch.object(S, "resolve", return_value=img),
          patch.object(S, "build_history", return_value=[row]),
          patch.object(S.Registry, "index_digest", **tag_lookup),
          contextlib.redirect_stdout(out)):
        S.main(["history", "--at-digest", SNAP])
    return out.getvalue(), row


class TestHistorySnapshotLabel(unittest.TestCase):
    def test_tag_still_on_the_snapshot_keeps_its_label(self):
        out, row = _run(return_value=SNAP)
        self.assertEqual(row["tags"], ["latest"])
        self.assertIn("*CURRENT", out)

    def test_moved_tag_is_not_claimed_for_the_snapshot(self):
        out, row = _run(return_value=OTHER)
        self.assertEqual(row["tags"], [])
        self.assertNotIn("*CURRENT", out)
        self.assertNotIn("latest", out.split("-" * 20, 1)[1].split("every image", 1)[0])

    def test_unreadable_tag_is_not_claimed_either(self):
        out, row = _run(side_effect=S.RegistryError("registry down"))
        self.assertEqual(row["tags"], [])
        self.assertNotIn("*CURRENT", out)

    def test_example_diff_names_the_snapshot_not_the_moved_tag(self):
        out, _ = _run(return_value=OTHER)
        self.assertIn(f"diff {SNAP} {SNAP}", out)


if __name__ == "__main__":
    unittest.main()
