"""`check` only trusts a saved state that was written for the image it watches."""
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


def _state(**identity):
    return json.dumps(dict(_image(1), version="1", **identity))


class TestCheckState(unittest.TestCase):
    def _check(self, state_text):
        previous, current = _image(1), _image(2)
        resolved = []

        def resolve(reg, ref, light=False):
            resolved.append(ref)
            return dict(current if ref == "latest" else previous, ref=ref)

        def packages(reg, img, ref, directory, notes):
            version = img["annotations"]["org.opencontainers.image.version"]
            return S.PackageTable({"trivalent": pkg("trivalent", version + ".0-1.fc45")})

        with tempfile.TemporaryDirectory() as directory:
            state, report, output = (Path(directory) / name
                                     for name in ("state.json", "report.md", "outputs"))
            state.write_text(state_text)
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    patch.object(S, "tag_exists", return_value=None), \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory,
                             "--scan", "0", "--no-fast", "--no-audit", "--no-bodhi",
                             "--prune-days", "0"])
            self.assertEqual(rc, 0)
            return resolved, json.loads(state.read_text()), output.read_text(), err.getvalue()

    def test_state_of_another_architecture_is_not_a_baseline(self):
        resolved, saved, output, err = self._check(_state(image="ghcr.io/x/y", arch="arm64"))
        self.assertEqual(resolved, ["latest"])
        self.assertIn("verdict=unknown\n", output)
        self.assertIn("ghcr.io/x/y (arm64)", err)
        self.assertEqual((saved["image"], saved["arch"]), ("ghcr.io/x/y", "amd64"))
        self.assertEqual(saved["digest"], _image(2)["digest"])

    def test_state_of_another_image_is_not_a_baseline(self):
        resolved, _saved, output, _err = self._check(_state(image="ghcr.io/x/other", arch="amd64"))
        self.assertEqual(resolved, ["latest"])
        self.assertIn("verdict=unknown\n", output)

    def test_own_state_is_the_baseline(self):
        resolved, saved, output, _err = self._check(_state(image="ghcr.io/x/y", arch="amd64"))
        self.assertEqual(resolved, ["latest", _image(1)["digest"]])
        self.assertEqual(saved["prev_digest"], _image(1)["digest"])
        self.assertNotIn("verdict=unknown", output)

    def test_state_without_identity_is_still_trusted(self):
        resolved, saved, _output, _err = self._check(_state())
        self.assertEqual(resolved, ["latest", _image(1)["digest"]])
        self.assertEqual(saved["arch"], "amd64")

    def test_state_that_is_not_an_object_counts_as_no_state(self):
        for text in ("[]", "null", '"x"', "7"):
            with self.subTest(text=text):
                resolved, saved, output, _err = self._check(text)
                self.assertEqual(resolved, ["latest"])
                self.assertIn("verdict=unknown\n", output)
                self.assertEqual(saved["digest"], _image(2)["digest"])


if __name__ == "__main__":
    unittest.main()
