"""By default the backlog audit looks at every pool source the image has."""
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class _NoErrata:
    failed = skipped = 0

    def updates_for_src(self, src, rel):
        return []


class TestBacklogDefaultLimit(unittest.TestCase):
    def test_no_candidate_is_cut_off_by_default(self):
        pkgs = S.PackageTable({s: pkg(s, "1-1.fc45") for s in S.BACKLOG_POOL})
        _rows, cov = S.security_backlog(pkgs, "F45", _NoErrata())
        self.assertEqual(cov["checked"], len(S.BACKLOG_POOL))
        self.assertEqual(cov["skipped"], 0)

    def test_disabled_bodhi_is_rejected_before_registry_access(self):
        with patch.object(S, "_registry") as registry, self.assertRaises(SystemExit) as err:
            S.main(["backlog", "--no-bodhi"])
        self.assertEqual(err.exception.code, 2)
        registry.assert_not_called()

    def test_the_cli_default_is_uncapped(self):
        seen = []
        with patch.object(S, "cmd_backlog", side_effect=lambda args: seen.append(args) or 0):
            S.main(["backlog"])
        self.assertIsNone(seen[0].backlog_candidates)

    def test_versioned_sources_do_not_consume_other_pool_entries(self):
        srcs = S.BACKLOG_POOL | {"python3.13", "python3.14"}
        pkgs = {s: pkg(s, "1-1.fc45") for s in srcs}
        _rows, cov = S.security_backlog(pkgs, "F45", _NoErrata())
        self.assertEqual(cov["checked"], len(srcs))
        self.assertEqual(cov["skipped"], 0)

    def test_installed_copr_source_is_ineligible_not_missing(self):
        p = dict(pkg("bubblewrap", "0.13.1-1.restricted"), vendor="Fedora Copr - user secureblue")
        _rows, cov = S.security_backlog({p["name"]: p}, "F45", _NoErrata())
        self.assertNotIn("bubblewrap", cov["pool_missing"])
        self.assertEqual(cov["pool_ineligible"], ["bubblewrap"])
        self.assertIn("bubblewrap", S.coverage_line(cov).en)


if __name__ == "__main__":
    unittest.main()
