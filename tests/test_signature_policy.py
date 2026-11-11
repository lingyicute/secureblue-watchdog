"""Offline regressions for fail-closed signature verification."""
import contextlib
import io
import types
import unittest
from unittest.mock import patch

from test_sbwatch import S


class TestRequiredSignatures(unittest.TestCase):
    def test_cli_rejects_missing_key_before_any_registry_access(self):
        commands = (["tags"], ["history"], ["layers", "a", "b"], ["pkgs"],
                    ["diff", "a", "b"], ["backlog"], ["check"])
        for command in commands:
            with self.subTest(command=command), \
                    patch.object(S, "_registry", side_effect=AssertionError("network reached")), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as exc:
                    S.main(command + ["--require-cosign"])
                self.assertEqual(exc.exception.code, 2)
                self.assertIn("--cosign-pub", err.getvalue())

    def test_verifier_rejects_required_verification_without_a_key(self):
        with self.assertRaises(SystemExit):
            S.verify_cosign_image("ghcr.io/x/y@sha256:" + "a" * 64, None, require=True)

    def test_resolved_helper_rejects_required_verification_without_a_key(self):
        args = types.SimpleNamespace(cosign_pub=None, require_cosign=True)
        with self.assertRaises(SystemExit):
            S.maybe_verify_resolved(S.Registry("x/y"), {"digest": "sha256:" + "a" * 64}, args)

    def test_optional_verification_can_still_be_skipped(self):
        self.assertFalse(S.verify_cosign_image("x/y:latest", None))
        self.assertFalse(S.maybe_verify_resolved(S.Registry("x/y"), {},
                                                types.SimpleNamespace()))

    def _history(self, verify):
        args = types.SimpleNamespace(image="x/y", arch="amd64", scan=2, days=0,
                                     to="latest", cosign_pub="key.pub", require_cosign=True)
        rows = []
        for i in (2, 1):
            digest = "sha256:" + str(i) * 64
            rows.append({"digest": digest, "platform_digest": digest,
                         "created": f"2026-01-0{i}T00:00:00Z", "version": str(i),
                         "inputhash": "", "kernel": "", "tags": ["latest"] if i == 2 else [],
                         "image": {"digest": digest}, "from_prev": None,
                         "same_input_as_prev": False})
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "build_history", return_value=rows), \
                patch.object(S, "maybe_verify_resolved", verify), \
                contextlib.redirect_stdout(io.StringIO()):
            S.cmd_history(args)
        return rows

    def test_history_verifies_every_listed_image(self):
        from unittest.mock import Mock
        verify = Mock(return_value=True)
        rows = self._history(verify)
        self.assertEqual([call.args[1] for call in verify.call_args_list],
                         [row["image"] for row in rows])

    def test_history_aborts_when_required_verification_fails(self):
        from unittest.mock import Mock
        with self.assertRaises(SystemExit):
            self._history(Mock(side_effect=SystemExit("signature rejected")))


if __name__ == "__main__":
    unittest.main()
