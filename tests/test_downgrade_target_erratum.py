"""Rolling back to an older build must not count that build's old erratum as a fix."""
import unittest

from test_sbwatch import S, pkg

LD = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
      "total_size_b": 100, "download_bytes": 100, "download_pct": 100,
      "changed_packages_from_chunks": ["foo"], "changed_chunks": []}


class _Bodhi:
    failed = skipped = 0
    truncated_src: set = set()

    def __init__(self, ups):
        self._ups = ups

    def updates_for_src(self, src, release):
        return list(self._ups)


class TestDowngradeTargetErratum(unittest.TestCase):
    def test_downgrade_to_build_with_old_urgent_erratum_stays_consider(self):
        bodhi = _Bodhi([
            {"alias": "FEDORA-2026-oldcrit", "type": "security", "status": "stable",
             "severity": "urgent", "title": "", "notes": "CVE-2026-1111",
             "cves": ["CVE-2026-1111"], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.1-1.fc45"]},
            {"alias": "FEDORA-2026-newsec", "type": "security", "status": "stable",
             "severity": "high", "title": "", "notes": "CVE-2026-2222",
             "cves": ["CVE-2026-2222"], "bugs": [], "date_approved": None,
             "nvrs": ["foo-1.2-1.fc45"]},
        ])
        old, new = pkg("foo", "1.2-1.fc45"), pkg("foo", "1.1-1.fc45")
        ch = [{"name": "foo", "old": old, "new": new, "src": "foo", "dir": "downgrade",
               "cls": S.classify_change(old, new, "F45", bodhi)}]
        diff = {"added": [], "removed": [], "changed": ch, "downgrades": ch,
                "count_a": 1, "count_b": 1}
        v = S.verdict_of(diff, LD, {})
        self.assertEqual(v["level"], "consider")
        notice = v["secureblue_notification"]
        self.assertEqual(notice["level"], "major")
        self.assertEqual(notice["level_without_advisories"], "none")
        self.assertEqual(notice["security_advisory_count"], 1)
        self.assertEqual(v["cves"], [])
        self.assertNotIn("escalated_by_secureblue_rule", v)
        self.assertEqual(v["already_had"], [])
        exported = S._comparison_json({"a": {"ref": "old", "digest": "d1"},
                                       "b": {"ref": "new", "digest": "d2"},
                                       "diff": diff, "verdict": v, "layers": LD})
        row, = exported["changed"]
        self.assertFalse(row["security"])
        self.assertEqual(row["cves"], [])
        self.assertEqual(row["aliases"], [])
        self.assertEqual([x["alias"] for x in row["already_had"]], ["FEDORA-2026-newsec"])

    def test_downgrade_nonstable_errata_are_omitted_from_report_groups(self):
        bodhi = _Bodhi([
            {"alias": "FEDORA-2026-obs", "type": "security", "status": "obsolete",
             "severity": "high", "title": "", "notes": "", "cves": [], "bugs": [],
             "date_approved": None, "nvrs": ["foo-1.1-1.fc45"]},
        ])
        old, new = pkg("foo", "1.2-1.fc45"), pkg("foo", "1.1-1.fc45")
        ch = [{"name": "foo", "old": old, "new": new, "src": "foo", "dir": "downgrade",
               "cls": S.classify_change(old, new, "F45", bodhi)}]
        g, = S.group_by_src(ch)
        self.assertEqual(g["unreleased"], [])

    def test_rollback_target_critical_erratum_is_not_credited_in_level_basis_or_fail_reason(self):
        import contextlib, io, os, tempfile
        from pathlib import Path
        from unittest.mock import patch
        bodhi = _Bodhi([
            {"alias": "FEDORA-2026-oldcrit", "type": "security", "status": "stable",
             "severity": "urgent", "title": "", "notes": "",
             "cves": [], "bugs": [], "date_approved": None, "nvrs": ["foo-1.1-1.fc45"]},
            {"alias": "FEDORA-2026-barlow", "type": "security", "status": "stable",
             "severity": "low", "title": "", "notes": "CVE-2026-3333",
             "cves": ["CVE-2026-3333"], "bugs": [], "date_approved": None, "nvrs": ["bar-2.1-1.fc45"]},
        ])
        pa = S.PackageTable({"foo": pkg("foo", "1.2-1.fc45"), "bar": pkg("bar", "2.0-1.fc45")})
        pb = S.PackageTable({"foo": pkg("foo", "1.1-1.fc45"), "bar": pkg("bar", "2.1-1.fc45")})
        old_img = {"digest": "sha256:" + "1" * 64, "index_digest": "sha256:" + "1" * 64,
                   "created": "2026-11-16T00:00:00Z", "layers": [], "annotations": {}}
        new_img = {"digest": "sha256:" + "2" * 64, "index_digest": "sha256:" + "2" * 64,
                   "created": "2026-11-17T00:00:00Z", "layers": [], "annotations": {}}
        with tempfile.TemporaryDirectory() as td:
            state, report, out = Path(td) / "state.json", Path(td) / "report.md", Path(td) / "out"
            state.write_text('{"digest": "' + old_img["digest"] + '"}')
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=lambda r, ref, **k: dict(
                        new_img if ref == "latest" else old_img, ref=ref)), \
                    patch.object(S, "load_pkglist", side_effect=lambda r, img, *a:
                        pa if img["digest"] == old_img["digest"] else pb), \
                    patch.object(S, "Bodhi", return_value=bodhi), \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(out)}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                S.main(["check", "--image", "x/y", "--state", str(state), "--report", str(report),
                        "--cache-dir", td, "--scan", "0", "--no-fast", "--no-audit", "--prune-days", "0"])
            data = S.json.loads(Path(str(report) + ".json").read_text())
            self.assertEqual(data["verdict"]["level"], "update-now")
            self.assertEqual(data["verdict"]["secureblue_notification"]["level"], "major")
            self.assertNotIn("notification rule classifies this as major", data["verdict"]["level_basis"])
            self.assertNotIn("secureblue treats this update as major", out.read_text())


if __name__ == "__main__":
    unittest.main()
