"""One Bodhi lookup that fails out of the blue is tried a second time."""
import contextlib
import io
import json
import unittest

from test_sbwatch import S, _FakeResp


def _ask(outcomes, **kwargs):
    calls = []

    def fake(url, timeout=None):
        calls.append(url)
        if not outcomes[min(len(calls), len(outcomes)) - 1]:
            raise OSError("timed out")
        return _FakeResp(json.dumps(
            {"total": 1, "updates": [{"alias": "FEDORA-2026-1", "builds": []}]}).encode())

    bodhi = S.Bodhi(cache_dir=None, sleep=0, **kwargs)
    saved = S.urllib.request.urlopen
    S.urllib.request.urlopen = fake
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            updates = bodhi.updates_for_src("curl", "F45")
    finally:
        S.urllib.request.urlopen = saved
    return bodhi, updates, calls


class TestBodhiRetriesOnce(unittest.TestCase):
    def test_a_single_miss_no_longer_leaves_a_coverage_gap(self):
        bodhi, updates, calls = _ask([False, True])
        self.assertEqual([u["alias"] for u in updates], ["FEDORA-2026-1"])
        self.assertEqual((bodhi.failed, bodhi._streak, bodhi.down), (0, 0, False))
        self.assertEqual(len(calls), 2)

    def test_the_retry_is_an_api_call_like_any_other(self):
        bodhi, _, _ = _ask([False, True])
        self.assertEqual(bodhi.calls, 2)

    def test_two_misses_count_as_one_failed_lookup(self):
        bodhi, updates, calls = _ask([False])
        self.assertEqual(updates, [])
        self.assertEqual((bodhi.failed, len(calls)), (1, 2))

    def test_no_retry_once_the_call_budget_is_spent(self):
        bodhi, updates, calls = _ask([False], max_calls=1)
        self.assertEqual(updates, [])
        self.assertEqual((bodhi.failed, len(calls)), (1, 1))


if __name__ == "__main__":
    unittest.main()
