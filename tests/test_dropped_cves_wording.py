"""CVE ids a new changelog no longer mentions are not "fixes the update removes"."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


class TestDroppedCvesWording(unittest.TestCase):
    def _check(self):
        def image(n):
            digest = "sha256:" + str(n) * 64
            return {"digest": digest, "index_digest": digest,
                    "created": f"2026-01-0{n}T00:00:00Z", "layers": [],
                    "annotations": {"org.opencontainers.image.version": str(n)}}

        older, newer = image(1), image(2)

        def resolve(reg, ref, light=False):
            return dict(newer if ref in ("latest", newer["digest"]) else older, ref=ref)

        def packages(reg, img, ref, directory, notes):
            # the new build's changelog was trimmed: the old CVE entry is gone
            if img["digest"] == older["digest"]:
                return S.PackageTable({"curl": pkg("curl", "8.1-1.fc45", changelog=[
                    {"time": 1, "text": "Fix CVE-2026-12345"}])})
            return S.PackageTable({"curl": pkg("curl", "8.2-1.fc45")})

        with tempfile.TemporaryDirectory() as directory:
            state, report = Path(directory) / "state.json", Path(directory) / "report.md"
            state.write_text(json.dumps({"digest": older["digest"], "version": "1",
                                         "created": older["created"]}))
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "resolve", side_effect=resolve), \
                    patch.object(S, "load_pkglist", side_effect=packages), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--state", str(state),
                             "--report", str(report), "--cache-dir", directory,
                             "--scan", "0", "--no-fast", "--no-audit", "--no-bodhi",
                             "--prune-days", "0"])
            self.assertEqual(rc, 0)
            return (report.read_text(encoding="utf-8"),
                    json.loads(Path(str(report) + ".json").read_text()))

    def test_neither_the_section_nor_the_evidence_claims_a_removed_fix(self):
        md, result = self._check()
        self.assertEqual(result["verdict"]["cves_dropped"], ["CVE-2026-12345"])
        for overclaim in ("REMOVES", "会移除的修复", "DROPS fixes", "丢失的修复"):
            self.assertNotIn(overclaim, md)
        self.assertIn("## CVE ids the new changelogs no longer mention (1 source package(s))", md)
        self.assertIn("## 新版更新日志不再提及的 CVE 编号（1 个源码包）", md)
        self.assertIn("- `curl`: no longer mentions CVE-2026-12345", md)
        self.assertIn("no longer mentioned/不再提及: CVE-2026-12345", md)


if __name__ == "__main__":
    unittest.main()
