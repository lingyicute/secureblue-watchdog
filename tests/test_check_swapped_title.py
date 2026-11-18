"""When check auto-swaps an explicit newer --a, the title shows the newer version."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestCheckSwappedTitle(unittest.TestCase):
    def test_title_carries_the_newer_sides_version_after_auto_swap(self):
        older = {"digest": "sha256:" + "1" * 64, "index_digest": "sha256:" + "1" * 64,
                 "created": "2026-11-04T16:49:40Z", "layers": [],
                 "annotations": {"org.opencontainers.image.version": "44.20261104.0"}}
        newer = {"digest": "sha256:" + "2" * 64, "index_digest": "sha256:" + "2" * 64,
                 "created": "2026-11-16T03:44:35Z", "layers": [],
                 "annotations": {"org.opencontainers.image.version": "45.20261116.0"}}

        def resolve(reg, ref, light=False):
            return dict(older if ref == "44" else newer, ref=ref)

        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist",
                                 side_effect=lambda reg, img, ref, d, n: S.PackageTable(
                                     {"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc45")})), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--to", "44", "--a", "latest",
                             "--state", str(state), "--report", str(report),
                             "--cache-dir", td, "--scan", "0", "--no-fast",
                             "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            data = json.loads(Path(str(report) + ".json").read_text())
            self.assertEqual((data["from_digest"], data["digest"]), (older["digest"], newer["digest"]))
            self.assertEqual(data["version"], "45.20261116.0")
            self.assertEqual(data["watched_digest"], older["digest"])
            self.assertEqual(data["watched_version"], "44.20261104.0")
            self.assertEqual(json.loads(state.read_text())["digest"], older["digest"])
            self.assertIn("44 -> latest (45.20261116.0)", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
