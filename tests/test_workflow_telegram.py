"""A configured Telegram destination must acknowledge the report before checkpointing."""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from test_sbwatch import workflow_python


class TestWorkflowTelegram(unittest.TestCase):
    def _send(self, response):
        script = workflow_python("Push to Telegram")
        env = {"TELEGRAM_BOT_TOKEN": "fake", "TELEGRAM_CHAT_ID": "42"}
        reply = {"side_effect": response} if isinstance(response, Exception) else {
            "return_value": io.BytesIO(json.dumps(response).encode())}
        out = io.StringIO()
        with patch.dict("os.environ", env), patch("urllib.request.urlopen", **reply), redirect_stdout(out):
            exec(compile(script, "telegram step", "exec"), {})
        return out.getvalue()

    def test_only_positive_acknowledgement_succeeds(self):
        self.assertIn("acknowledged", self._send({"ok": True, "result": {"message_id": 32}}))
        for response in ({"ok": False}, {"ok": 1}, [], {}):
            with self.subTest(response=response), self.assertRaises(SystemExit):
                self._send(response)

    def test_transport_error_does_not_write_request_url(self):
        error = HTTPError("https://example.invalid/private", 403, "Forbidden", {}, None)
        with self.assertRaises(SystemExit) as err:
            self._send(error)
        self.assertEqual(str(err.exception), "Telegram delivery failed (HTTP 403)")
