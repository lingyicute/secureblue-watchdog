"""`check` only says "N builds since your last look" when it diffs against that image."""
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


IMAGES = [_image(n) for n in (1, 2, 3)]          # oldest first; the last one is `latest`
NOTE_EN, NOTE_ZH = "this image is not the only new one", "这不是唯一的新镜像"


def _resolve(reg, ref, light=False):
    return dict(next((i for i in IMAGES if i["digest"] == ref), IMAGES[-1]), ref=ref)


def _history(reg, scan=12, days=7, to="latest", warn=None, cur=None):
    return [{"digest": i["index_digest"], "platform_digest": i["digest"],
             "created": i["created"],
             "version": i["annotations"]["org.opencontainers.image.version"]}
            for i in reversed(IMAGES)]


def _packages(reg, img, ref, directory, notes):
    return S.PackageTable({"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc45")})


class TestSinceLastLookNote(unittest.TestCase):
    def _report(self, *extra):
        with tempfile.TemporaryDirectory() as directory:
            state, report = Path(directory) / "state.json", Path(directory) / "report.md"
            # last look: the oldest build; builds 2 and 3 were pushed after it
            state.write_text(json.dumps({"digest": IMAGES[0]["digest"],
                                         "created": IMAGES[0]["created"]}))
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=_resolve), \
                    patch.object(S, "build_history", side_effect=_history), \
                    patch.object(S, "load_pkglist", side_effect=_packages), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory,
                             "--scan", "3", "--no-fast", "--no-audit", "--no-bodhi",
                             "--prune-days", "0", *extra])
            self.assertEqual(rc, 0)
            return report.read_text(encoding="utf-8")

    def test_the_note_goes_with_a_diff_against_the_last_seen_image(self):
        md = self._report()
        self.assertIn(NOTE_EN + ": 1 build(s)", md)
        self.assertIn(NOTE_ZH, md)

    def test_an_explicit_baseline_is_not_called_your_last_image(self):
        md = self._report("--a", IMAGES[1]["digest"])
        self.assertNotIn(NOTE_EN, md)
        self.assertNotIn(NOTE_ZH, md)


if __name__ == "__main__":
    unittest.main()
