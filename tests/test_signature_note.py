"""A signature check that never ran is not reported as a failed signature."""
import argparse
import contextlib
import io
import tempfile
import types
import unittest
from unittest.mock import patch

from test_sbwatch import S

DIGEST = "sha256:" + "a" * 64
REF = "ghcr.io/x/y@" + DIGEST


class TestSignatureNote(unittest.TestCase):
    def _note(self, outcome):
        args = argparse.Namespace(cosign_pub="cosign.pub", require_cosign=False)
        notes = []
        with patch.dict(S._COSIGN_RESULTS, clear=True), \
                patch.object(S, "verify_cosign_image", return_value=outcome):
            ok = S.maybe_verify_resolved(types.SimpleNamespace(host="ghcr.io", repo="x/y"),
                                         {"digest": DIGEST}, args, notes)
        return ok, notes[-1].en, notes[-1].zh

    def test_a_check_that_could_not_run_is_not_called_failed(self):
        ok, en, zh = self._note(None)
        self.assertIs(ok, False)
        self.assertIn("NOT RUN", en)
        self.assertNotIn("FAILED", en)
        self.assertNotIn("失败", zh)

    def test_a_rejected_signature_still_reads_failed(self):
        ok, en, _zh = self._note(False)
        self.assertIs(ok, False)
        self.assertIn("FAILED (tolerated)", en)

    def test_a_verified_signature_reads_passed(self):
        ok, en, _zh = self._note(True)
        self.assertIs(ok, True)
        self.assertIn("PASSED", en)

    def _verify(self, which, **run):
        with tempfile.NamedTemporaryFile() as key, \
                patch.object(S.shutil, "which", return_value=which), \
                patch.object(S.subprocess, "run", **run), \
                contextlib.redirect_stderr(io.StringIO()):
            return S.verify_cosign_image(REF, key.name)

    def test_missing_cosign_binary_is_none(self):
        self.assertIsNone(self._verify(None, side_effect=AssertionError("must not run")))

    def test_missing_key_file_is_none(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(S.verify_cosign_image(REF, "/nonexistent/cosign.pub"))

    def test_timeout_is_none(self):
        boom = S.subprocess.TimeoutExpired("cosign", 90)
        self.assertIsNone(self._verify("/usr/bin/cosign", side_effect=boom))

    def test_nonzero_exit_is_a_real_failure(self):
        done = types.SimpleNamespace(returncode=1, stdout="", stderr="no matching signatures")
        self.assertIs(self._verify("/usr/bin/cosign", return_value=done), False)


if __name__ == "__main__":
    unittest.main()
