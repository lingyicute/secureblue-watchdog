"""Watching a pinned stream tag (`44`) ignores builds of another major (`45`)."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_sbwatch import S, pkg


def _img(ch, ver, created):
    dig = "sha256:" + ch * 64
    return {"digest": dig, "index_digest": dig, "is_index": True, "created": created,
            "annotations": {"org.opencontainers.image.version": ver},
            "layers": [{"digest": "sha256:" + "f" * 64, "size": 1, "stability": 0.0,
                        "components": ["bigfiles/rpmdb.sqlite"]}]}


class TestStreamMajorHistory(unittest.TestCase):
    def test_history_for_tag_44_skips_f45_and_earlier_br_next_45_builds(self):
        # Mirrors live ghcr.io/secureblue/silverblue-main-hardened on 2026-11-04:
        # 5afa87a-45 (45.20261104.0 @ 16:39Z) preceded 44 (44.20261104.0 @ 16:49Z).
        prev44 = _img("1", "44.20261104.0", "2026-11-04T14:01:09Z")
        early45 = _img("2", "45.20261104.0", "2026-11-04T16:39:04Z")
        cur44 = _img("3", "44.20261104.0", "2026-11-04T16:49:40Z")
        later45 = _img("4", "45.20261105.0", "2026-11-05T17:10:53Z")
        imgs = {i["digest"]: i for i in (prev44, early45, cur44, later45)}
        tags = ["sha256-" + i["digest"][7:] + ".sig"
                for i in (prev44, early45, cur44, later45)]
        with patch.object(S, "list_tags", return_value=tags), \
                patch.object(S, "resolve",
                             side_effect=lambda reg, ref, light=False: dict(imgs[ref], ref=ref)):
            rows44 = S.build_history(None, scan=5, days=0, to="44", cur=cur44)
            rows_latest = S.build_history(None, scan=5, days=0, to="latest", cur=later45)
        self.assertEqual([r["digest"] for r in rows44], [cur44["digest"], prev44["digest"]])
        self.assertEqual(len(rows_latest), 4)

    def test_check_dated_fallback_for_tag_44_skips_f45_and_uses_stream_dated_tag(self):
        cur44 = _img("5", "44.20260109.0", "2026-01-09T20:00:00Z")
        day_f45 = _img("6", "45.20260109.0", "2026-01-09T10:00:00Z")
        prev44 = _img("7", "44.20260108.0", "2026-01-08T10:00:00Z")
        by_tag = {"20260109": day_f45, "20260108-44": prev44, "44": cur44}

        with tempfile.TemporaryDirectory() as td:
            state, report = Path(td) / "state.json", Path(td) / "report.md"
            with patch.object(S.Registry, "_token", return_value=None), \
                    patch.object(S, "tag_exists",
                                 side_effect=lambda r, t, warn=None:
                                 by_tag[t]["index_digest"] if t in by_tag else None), \
                    patch.object(S, "resolve",
                                 side_effect=lambda r, ref, light=False: dict(by_tag[ref], ref=ref)), \
                    patch.object(S, "load_pkglist",
                                 side_effect=lambda r, img, ref, d, n: S.PackageTable(
                                     {"bash": pkg("bash", f"5.3-{img['digest'][7]}.fc44")})), \
                    patch("time.time", return_value=1768003200), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = S.main(["check", "--image", "x/y", "--to", "44", "--state", str(state),
                             "--report", str(report), "--cache-dir", td, "--scan", "0",
                             "--no-fast", "--no-audit", "--no-bodhi", "--prune-days", "0"])
            self.assertEqual(rc, 0)
            doc = json.loads(Path(str(report) + ".json").read_text())
            self.assertEqual(doc["from"], "20260108-44")


if __name__ == "__main__":
    unittest.main()
