"""cmd_backlog renders missing Bodhi aliases as an em dash."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestBacklogNullAliasDisplay(unittest.TestCase):
    def test_null_alias_renders_as_em_dash_in_cmd_backlog(self):
        class _Bodhi:
            failed = skipped = 0
            truncated_src = set()

            def __init__(self, **kw):
                pass

            def updates_for_src(self, src, rel):
                return [{"alias": None, "type": "security", "severity": "high",
                         "status": "stable", "notes": "", "cves": [], "bugs": [],
                         "nvrs": ["curl-8.9.2-1.fc45"], "build_epochs": {}}]

        img = {"digest": "sha256:" + "1" * 64, "layers": [],
               "annotations": {"org.opencontainers.image.version": "45.20261124.0"}}
        out = io.StringIO()
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "resolve", return_value=img), \
                patch.object(S, "load_pkglist",
                             return_value=S.PackageTable({"curl": pkg("curl", "8.9.1-1.fc45")})), \
                patch.object(S, "Bodhi", _Bodhi), \
                contextlib.redirect_stdout(out):
            S.main(["backlog", "latest"])
        self.assertNotIn("None", out.getvalue())
        self.assertIn("high      —", out.getvalue())


if __name__ == "__main__":
    unittest.main()
