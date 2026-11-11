"""The backlog audit spends its candidate limit on security-sensitive sources first."""
import unittest

from test_sbwatch import S


class _NoErrata:
    failed = skipped = 0

    def __init__(self):
        self.asked = []

    def updates_for_src(self, src, release):
        self.asked.append(src)
        return []


def _pkgs(*sources):
    return {s: {"name": s, "src": s, "version": "1", "release": "1.fc45",
                "evr": "1-1.fc45", "srpm": f"{s}-1-1.fc45"} for s in sources}


class TestBacklogPriority(unittest.TestCase):
    def test_limit_cuts_the_less_sensitive_sources(self):
        bodhi = _NoErrata()
        _rows, cov = S.security_backlog(
            _pkgs("audit", "bind", "systemd", "webkitgtk"), "F45", bodhi, limit=2)
        self.assertEqual(bodhi.asked, ["systemd", "webkitgtk"])
        self.assertEqual(cov["skipped_names"], ["audit", "bind"])

    def test_versioned_interpreter_source_counts_as_sensitive(self):
        bodhi = _NoErrata()
        S.security_backlog(_pkgs("audit", "python3.15"), "F45", bodhi, limit=1)
        self.assertEqual(bodhi.asked, ["python3.15"])

    def test_name_order_is_kept_within_each_half(self):
        bodhi = _NoErrata()
        S.security_backlog(_pkgs("git", "audit", "systemd", "glibc"), "F45", bodhi)
        self.assertEqual(bodhi.asked, ["glibc", "systemd", "audit", "git"])


if __name__ == "__main__":
    unittest.main()
