"""The requested snapshot, not today's latest push, anchors its history."""
import unittest
from unittest.mock import patch

from test_sbwatch import S
from test_stream_major_history import _img


class TestHistoryAnchor(unittest.TestCase):
    def test_old_dated_tag_places_scan_window_at_its_signature(self):
        # On GHCR --to 20261114 --scan 3 returned two Nov 17 builds instead
        # of either of the predecessor builds of the requested snapshot.
        old = _img('1', '45.20261114.0', '2026-11-14T11:00:00Z')
        target = _img('2', '45.20261114.0', '2026-11-14T22:25:54Z')
        # One later image was signed before the target; it is still ineligible.
        later = _img('3', '45.20261115.0', '2026-11-15T01:00:00Z')
        tag = lambda img: 'sha256-' + img['digest'][7:] + '.sig'
        tags = [tag(old), tag(later), tag(target)] + [
            f'sha256-{i:064x}.sig' for i in range(100)]
        imgs = {img['digest']: img for img in (old, target, later)}
        with patch.object(S, 'list_tags', return_value=tags), \
                patch.object(S, 'resolve', side_effect=lambda _, dig, **kw: imgs[dig]):
            rows = S.build_history(None, scan=2, days=0, to='20261114', cur=target)
        self.assertEqual([row['digest'] for row in rows],
                         [target['digest'], old['digest']])

    def test_unsigned_anchor_does_not_yield_newer_builds(self):
        old = _img('1', '45.20261114.0', '2026-11-14T11:00:00Z')
        target = _img('2', '45.20261114.0', '2026-11-14T22:25:54Z')
        later = _img('3', '45.20261115.0', '2026-11-15T01:00:00Z')
        with patch.object(S, 'list_tags', return_value=[
                'sha256-' + img['digest'][7:] + '.sig' for img in (old, later)]), \
                patch.object(S, 'resolve', side_effect=[later, old]):
            rows = S.build_history(None, scan=2, days=0, to='20261114', cur=target)
        self.assertEqual([row['digest'] for row in rows],
                         [target['digest'], old['digest']])
