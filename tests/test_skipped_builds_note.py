"""The note about skipped builds shows the last-seen build time whole."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


def _image(n):
    digest = "sha256:" + str(n) * 64
    return {"digest": digest, "index_digest": digest, "created": f"2026-01-0{n}T00:00:00Z",
            "layers": [], "annotations": {"org.opencontainers.image.version": str(n)}}


class TestSkippedBuildsNote(unittest.TestCase):
    def test_last_seen_time_carries_no_chars_not_shown_marker(self):
        seen, skipped, current = _image(1), _image(2), _image(3)
        rows = [{"digest": i["digest"], "platform_digest": i["digest"],
                 "created": i["created"],
                 "version": i["annotations"]["org.opencontainers.image.version"]}
                for i in (current, skipped, seen)]

        def resolve(reg, ref, light=False):
            return dict(current if ref == "latest" else seen, ref=ref)

        def packages(reg, img, ref, directory, notes):
            version = img["annotations"]["org.opencontainers.image.version"]
            return S.PackageTable({"foo": pkg("foo", version + ".0-1.fc45")})

        with tempfile.TemporaryDirectory() as directory:
            state, report = Path(directory) / "state.json", Path(directory) / "report.md"
            state.write_text(json.dumps(dict(seen, version="1")))
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S, "build_history", return_value=rows), \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory,
                             "--no-fast", "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            markdown = report.read_text(encoding="utf-8")
        self.assertIn("1 build(s) were pushed after the build you last looked at "
                      "(2026-01-01T00:00:00)", markdown)
        self.assertIn("（2026-01-01T00:00:00）", markdown)
        self.assertNotIn("chars not shown", markdown)
        self.assertNotIn("个字符未显示", markdown)


if __name__ == "__main__":
    unittest.main()
