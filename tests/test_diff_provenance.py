"""A portable diff records the images actually compared, not mutable inputs alone."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_sbwatch import S
from test_check_state import _image


class TestDiffProvenance(unittest.TestCase):
    def test_export_follows_orientation(self):
        old, new = _image(1), _image(2)
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'diff.json'
            with patch.object(S.Registry, '_token', return_value=None), \
                    patch.object(S, 'resolve', side_effect=lambda reg, ref, **k:
                        dict(new if ref == 'latest' else old, ref=ref)), \
                    contextlib.redirect_stdout(io.StringIO()):
                S.main(['diff', 'latest', 'previous', '--exact', '0', '--json-out', str(out)])
            payload = json.loads(out.read_text())
        self.assertEqual((payload['from'], payload['to']), ('previous', 'latest'))
        self.assertEqual((payload['from_digest'], payload['digest']), (old['digest'], new['digest']))
