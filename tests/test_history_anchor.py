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

    def test_dated_tag_labels_anchor_to_snapshot_date(self):
        prev = _img('1', '44.20261103.0', '2026-11-03T14:00:00Z')
        target = _img('2', '44.20261104.0', '2026-11-04T16:00:00Z')
        tags = ['sha256-' + prev['digest'][7:] + '.sig',
                'sha256-' + target['digest'][7:] + '.sig',
                '20261103', '20261103-44', '20261104', '20261104-44',
                '20261120', '20261121', '20261122']
        by_tag = {'20261103': prev['digest'], '20261103-44': prev['digest'],
                  '20261104': target['digest'], '20261104-44': target['digest']}
        probed = []

        class _Reg:
            def index_digest(self, t):
                probed.append(t)
                return by_tag.get(t, 'sha256:' + '9' * 64)

        imgs = {img['digest']: img for img in (prev, target)}
        with patch.object(S, 'list_tags', return_value=tags),                 patch.object(S, 'resolve', side_effect=lambda _, dig, **kw: imgs[dig]):
            rows = S.build_history(_Reg(), scan=2, days=2, to='44', cur=target)
        self.assertNotIn('20261122', probed)
        self.assertIn('20261104-44', rows[0]['tags'])
        self.assertIn('20261103-44', rows[1]['tags'])


class TestHistoryAtDigest(unittest.TestCase):
    def test_watched_stream_can_be_named_without_re_resolving_tag(self):
        from unittest.mock import patch
        digest = "sha256:" + "a" * 64
        img = {"digest": digest, "index_digest": digest, "annotations": {}}
        row = {"digest": digest, "tags": ["44"], "version": "44.20261104.0",
               "inputhash": None, "kernel": None, "image": img}
        with (patch.object(S.Registry, "_token", return_value=None),
              patch.object(S, "resolve", return_value=img) as resolver,
              patch.object(S, "build_history", return_value=[row]) as history,
              patch.object(S.Registry, "index_digest", return_value=digest),
              patch("builtins.print")):
            self.assertEqual(S.main(["history", "--to", "44", "--at-digest", digest]), 0)
        self.assertEqual([c.args[1] for c in resolver.call_args_list], [digest])
        self.assertEqual(history.call_args.kwargs["to"], "44")
        self.assertIs(history.call_args.kwargs["cur"], img)
