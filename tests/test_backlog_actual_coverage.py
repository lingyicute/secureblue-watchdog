"""Backlog coverage counts only candidates whose errata were actually queried."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


def _empty_page(url, timeout=40):
    class _R:
        def __enter__(self):
            return io.BytesIO(b'{"total": 0, "updates": []}')

        def __exit__(self, *a):
            return False

    return _R()


class TestBacklogActualCoverage(unittest.TestCase):
    def test_budget_skipped_candidates_are_not_counted_as_queried(self):
        bodhi = S.Bodhi(cache_dir=None, sleep=0, max_calls=2)
        pkgs = {s: pkg(s, "1.0-1.fc45") for s in ("curl", "glibc", "kernel", "nss", "openssl")}
        with patch("urllib.request.urlopen", side_effect=_empty_page):
            _rows, cov = S.security_backlog(pkgs, "F45", bodhi, limit=10)
        self.assertEqual((cov["candidates"], cov["checked"], cov["skipped_queries"]), (5, 2, 3))
        line = S.coverage_line(cov)
        self.assertIn("2 of 5", line.en)
        self.assertIn("3 not queried (--max-bodhi)", line.en)
        self.assertIn("5 个候选源码包中查询了 2 个", line.zh)

    def test_failed_lookups_are_excluded_and_diff_failures_stay_separate(self):
        bodhi = S.Bodhi(cache_dir=None, sleep=0, max_calls=10)
        with patch("urllib.request.urlopen", side_effect=OSError("down")), \
                contextlib.redirect_stderr(io.StringIO()):
            bodhi.updates_for_src("adw-gtk3-theme", "F45")
            _rows, cov = S.security_backlog({"curl": pkg("curl", "8.9-1.fc45")}, "F45", bodhi)
        self.assertEqual((cov["candidates"], cov["checked"], cov["failed"]), (1, 0, 1))
        self.assertIn("0 of 1", S.coverage_line(cov).en)
        self.assertIn("1 failed", S.coverage_line(cov).en)

    def test_truncated_sources_are_recorded_and_printed_by_cmd_backlog(self):
        class _TruncBodhi:
            failed = skipped = 0
            truncated_src = {"kernel", "unrelated"}

            def __init__(self, **kw):
                pass

            def updates_for_src(self, src, rel):
                return []

        img = {"digest": "sha256:" + "1" * 64, "layers": [],
               "annotations": {"org.opencontainers.image.version": "45.20261116.0"}}
        out = io.StringIO()
        with patch.object(S.Registry, "_token", return_value=None),                 patch.object(S, "resolve", return_value=img),                 patch.object(S, "load_pkglist",
                             return_value=S.PackageTable({"kernel": pkg("kernel", "7.3-1.fc45")})),                 patch.object(S, "Bodhi", _TruncBodhi),                 contextlib.redirect_stdout(out):
            S.main(["backlog", "latest"])
        self.assertIn("errata list truncated for: kernel", out.getvalue())
        self.assertNotIn("unrelated", out.getvalue())


if __name__ == "__main__":
    unittest.main()
