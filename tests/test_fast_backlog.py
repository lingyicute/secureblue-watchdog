"""An identical rpmdb can still be behind a newly published Fedora update."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_check_state import _image
from test_sbwatch import S, pkg


class TestFastBacklog(unittest.TestCase):
    def _run(self, *flags):
        old, new = _image(1), _image(2)
        old['layers'] = new['layers'] = [{'digest': 'sha256:' + 'a' * 64,
            'size': 33504432, 'components': ['bigfiles/rpmdb.sqlite'], 'stability': 0}]
        packages = S.PackageTable({'dnf5': pkg('dnf5', '5.4.8.0-2.fc45')})
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / 'report.md'
            with patch.object(S.Registry, '_token', return_value=None), \
                    patch.object(S, 'resolve', side_effect=lambda reg, ref, **k:
                        dict(new if ref == 'latest' else old, ref=ref)), \
                    patch.object(S, 'load_pkglist', return_value=packages) as load, \
                    patch.object(S.Bodhi, 'updates_for_src', return_value=[]) as query, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                S.main(['check', '--a', 'older', '--scan', '0', '--cache-dir', tmp,
                        '--state', str(Path(tmp) / 'state'), '--report', str(report), *flags])
            return json.loads(Path(str(report) + '.json').read_text()), load.call_count, query.call_count

    def test_requested_audit_reads_shared_inventory_once(self):
        result, reads, calls = self._run()
        self.assertEqual((reads, calls), (1, 1))
        self.assertEqual(result['backlog_coverage']['checked'], 1)

    def test_no_audit_retains_the_manifest_only_optimization(self):
        result, reads, calls = self._run('--no-audit')
        self.assertEqual((reads, calls), (0, 0))
        self.assertEqual(result['verdict']['level'], 'no-change')

    def test_no_bodhi_is_not_an_empty_successful_audit(self):
        result, _, calls = self._run('--no-fast', '--no-bodhi')
        self.assertEqual(calls, 0)
        self.assertIsNone(result['backlog_coverage'])
        self.assertFalse(result['verdict']['backlog_audited'])
        self.assertIsNone(result['verdict']['backlog_count'])
