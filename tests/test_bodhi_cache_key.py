"""Every Bodhi cache key gets a file of its own."""
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S

UPDATE = {"alias": "FEDORA-2026-foobar", "type": "security", "severity": "high",
          "status": "stable", "title": "foo-bar-1.0-1.fc45", "notes": "", "bugs": [],
          "builds": [{"nvr": "foo-bar-1.0-1.fc45"}]}


class TestBodhiCacheKey(unittest.TestCase):
    def test_names_that_differ_only_in_punctuation_get_distinct_files(self):
        with tempfile.TemporaryDirectory() as directory:
            bodhi = S.Bodhi(cache_dir=directory)
            keys = ["foo-bar-F45", "foo_bar-F45", "foo.bar-F45", "foo+bar-F45",
                    "foo--bar-F45", "foo-bar_F45"]
            self.assertEqual(len({bodhi._cf(k) for k in keys}), len(keys))

    def test_a_plain_key_keeps_its_readable_name(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(os.path.basename(S.Bodhi(cache_dir=directory)._cf("kernel-F45")),
                             "bodhi-kernel_F45.json")

    def test_one_packages_cached_answer_is_not_served_as_anothers(self):
        answers = [{"updates": [UPDATE], "total": 1}, {"updates": [], "total": 0}]

        def urlopen(*_a, **_k):
            return io.BytesIO(json.dumps(answers.pop(0)).encode())

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(S.urllib.request, "urlopen", side_effect=urlopen):
            first = S.Bodhi(cache_dir=directory, sleep=0).updates_for_src("foo-bar", "F45")
            second = S.Bodhi(cache_dir=directory, sleep=0).updates_for_src("foo_bar", "F45")
        self.assertEqual([u["alias"] for u in first], ["FEDORA-2026-foobar"])
        self.assertEqual(second, [])
        self.assertEqual(answers, [])          # foo_bar was really asked for


if __name__ == "__main__":
    unittest.main()
