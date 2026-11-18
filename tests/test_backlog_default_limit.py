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

    def test_the_cli_default_is_that_limit(self):
        seen = []
        with patch.object(S, "cmd_backlog", side_effect=lambda args: seen.append(args) or 0):
            S.main(["backlog"])
        self.assertEqual(seen[0].backlog_candidates, len(S.BACKLOG_POOL))


if __name__ == "__main__":
    unittest.main()
