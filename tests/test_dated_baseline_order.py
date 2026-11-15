"""A dated tag newer than the watched image is no baseline for `check`."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


def _image(n, day):
    digest = "sha256:" + str(n) * 64
    return {"digest": digest, "index_digest": digest, "created": f"2026-01-{day:02d}T00:00:00Z",
            "layers": [],
            "annotations": {"org.opencontainers.image.version": f"44.202601{day:02d}.0"}}


OLDER, CUR, NEWER = _image(1, 3), _image(2, 4), _image(3, 14)


class TestDatedBaselineOrder(unittest.TestCase):
    def test_a_later_dated_tag_is_passed_over(self):
        probed = {}     # dated tag -> image, in probing order: yesterday's, then older

        def tag_exists(reg, tag, warn=None):
            if tag not in probed and len(probed) < 2:
                probed[tag] = (NEWER, OLDER)[len(probed)]
            return probed[tag]["index_digest"] if tag in probed else None

        def resolve(reg, ref, light=False):
            return dict(probed[ref] if ref in probed else CUR, ref=ref)

        def history(reg, scan=12, days=7, to="latest", warn=None, cur=None):
            return []

        def packages(reg, img, ref, directory, notes):
            return S.PackageTable({"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc44")})

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            state_path = Path(directory) / "state.json"
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "build_history", side_effect=history), \
                    patch.object(S, "tag_exists", side_effect=tag_exists), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--to", "44", "--state",
                             str(state_path), "--report", str(report),
                             "--cache-dir", directory, "--scan", "2", "--no-fast",
                             "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            doc = json.loads(Path(str(report) + ".json").read_text())
            state = json.loads(state_path.read_text())
        _newer_tag, older_tag = list(probed)
        self.assertEqual(doc["from"], older_tag)
        self.assertEqual(state["prev_digest"], OLDER["digest"])
        self.assertEqual(state["digest"], CUR["digest"])


if __name__ == "__main__":
    unittest.main()
