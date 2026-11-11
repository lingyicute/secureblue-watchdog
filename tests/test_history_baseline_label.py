"""A baseline picked from the build history is labelled like one from the state file."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


def _image(n):
    digest = "sha256:" + str(n) * 64
    return {"digest": digest, "index_digest": digest, "created": f"2026-01-0{n}T00:00:00Z",
            "layers": [], "annotations": {"org.opencontainers.image.version": f"45.2026010{n}.0"}}


PREV, CUR = _image(1), _image(2)


def _resolve(reg, ref, light=False):
    return dict(PREV if ref == PREV["digest"] else CUR, ref=ref)


def _packages(reg, img, ref, directory, notes):
    return S.PackageTable({"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc45")})


class TestHistoryBaselineLabel(unittest.TestCase):
    def _from_label(self, version):
        def history(reg, scan=12, days=7, to="latest", warn=None, cur=None):
            return [{"digest": CUR["index_digest"], "platform_digest": CUR["digest"],
                     "created": CUR["created"], "version": "45.20260102.0"},
                    {"digest": PREV["index_digest"], "platform_digest": PREV["digest"],
                     "created": PREV["created"], "version": version}]

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=_resolve), \
                    patch.object(S, "build_history", side_effect=history), \
                    patch.object(S, "load_pkglist", side_effect=_packages), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state",
                             str(Path(directory) / "state.json"), "--report", str(report),
                             "--cache-dir", directory, "--scan", "2", "--no-fast",
                             "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            return json.loads(Path(str(report) + ".json").read_text())["from"]

    def test_version_and_build_time(self):
        self.assertEqual(self._from_label("45.20260101.0"), "45.20260101.0 @ 2026-01-01T00:00:00")

    def test_a_build_without_a_version_annotation_is_not_titled_none(self):
        self.assertEqual(self._from_label(None), "2026-01-01T00:00:00")


if __name__ == "__main__":
    unittest.main()
