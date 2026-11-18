"""An optional historical candidate cannot stop inspection of a valid anchor."""
import io
import unittest
from unittest.mock import patch

import sbwatch as S


class TestProbeIntegrity(unittest.TestCase):
    def test_overlarge_tag_probe_reports_unknown(self):
        registry = S.Registry("test/watch")
        response = io.BytesIO(b"")
        response.headers = {"Content-Length": str(S.MAX_JSON_BYTES + 1)}
        warnings = []
        with patch.object(registry, "_open", return_value=response):
            self.assertIsNone(S.tag_exists(registry, "20261117", warn=warnings))
        self.assertEqual(len(warnings), 1)

    def test_digest_mismatch_is_diagnosed_and_candidate_skipped(self):
        bad, current = ("sha256:" + c * 64 for c in "ab")
        registry = S.Registry("test/watch")
        image = {"digest": current, "index_digest": current, "layers": [], "annotations": {},
                 "created": "2026-11-18T00:00:00Z"}
        response = io.BytesIO(b"{}")
        response.headers = {}
        warnings = []
        with patch.object(S, "list_tags", return_value=["sha256-" + bad[7:] + ".sig"]), \
             patch.object(registry, "_open", return_value=response):
            result = S.build_history(registry, cur=image, warn=warnings)
        self.assertEqual([row["digest"] for row in result], [current])
        self.assertEqual(len(warnings), 1)
