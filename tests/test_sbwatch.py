#!/usr/bin/env python3
"""Offline regression tests for sbwatch.py.

No network, no registry, no `rpm` module - everything here runs against the real
behaviour of the shipped code with in-memory fixtures. Run with:

    python3 tests/test_sbwatch.py            # or: python3 -m unittest discover -s tests

Each group is named after the finding it locks down, so a failure points straight
at the regression it guards:
  A1/A3  classify_change: errata for the OLD build, and unpushed errata
  A2     build_history rows must carry the platform digest
  A4     crosscheck_chunks must not invent "same version" claims
  A5     orient(): A must be the older build
  A6     rpmvercmp against rpm's own 91 upstream test vectors
  B1     Bodhi cache poisoning / CVEs that only live in bugs[].title
  D      dead code must stay dead
  E3     state writes are atomic
"""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sbwatch as S  # noqa: E402


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
def pkg(name, evr, src=None, changelog=(), epoch=""):
    """Mirror the dict package_list builds: `nvr` and `evr` are both present and
    epoch is a *string* (read_header does str(struct.unpack('>I', ...)))."""
    v, r = evr.split("-", 1) if "-" in evr else (evr, "")
    return {"name": name, "version": v, "release": r, "epoch": epoch, "arch": "x86_64",
            "evr": evr, "nvr": f"{name}-{evr}", "srpm": f"{src or name}-{evr}.src.rpm",
            "src": src or name, "changelog": [dict(t) for t in changelog]}


class FakeBodhi:
    """Stands in for S.Bodhi: `updates_for_src` answers from a canned dict."""

    def __init__(self, updates):
        self._u = updates
        self.failed = 0
        self.skipped = 0

    def updates_for_src(self, src, rel):
        return self._u.get(src, [])


# The live 20260916 -> latest delta that produced the original false positive:
# nss went 4.39.0-4 -> 4.39.0-5 (a bugfix), while the *old* build's erratum was
# a security/urgent one. Counting that old erratum invented an UPDATE NOW.
NSS_OLD = pkg("nss", "4.39.0-4.fc44", "nss",
              [{"time": 1, "text": "- Update to 4.39.0"}])
NSS_NEW = pkg("nss", "4.39.0-5.fc44", "nss",
              [{"time": 2, "text": "- Rebuild against new nspr"}])
NSS_UPDATES = {
    "nss": [
        {"alias": "FEDORA-2026-42a3a95e62", "type": "security", "severity": "urgent",
         "status": "stable", "nvrs": ["nss-4.39.0-4.fc44"], "notes": "CVE-2026-0001",
         "bugs": [], "title": "", "cves": []},
        {"alias": "FEDORA-2026-243a820a1c", "type": "bugfix", "severity": "unspecified",
         "status": "stable", "nvrs": ["nss-4.39.0-5.fc44"], "notes": "",
         "bugs": [], "title": "", "cves": []},
    ],
}


# --------------------------------------------------------------------------- #
# A6 - rpmvercmp must match rpm itself
# --------------------------------------------------------------------------- #
class TestRpmvercmp(unittest.TestCase):
    """Ported from rpm's own tests/rpmvercmp.at (91 vectors, scraped into JSON)."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "rpmvercmp_vectors.json")) as fh:
            cls.vectors = json.load(fh)

    def test_upstream_vectors(self):
        self.assertGreaterEqual(len(self.vectors), 90, "vector fixture looks truncated")
        bad = []
        for a, b, want in self.vectors:
            got = S.rpmvercmp(a, b)
            got = (got > 0) - (got < 0)
            if got != want:
                bad.append((a, b, want, got))
        self.assertEqual(bad, [], f"rpmvercmp disagrees with rpm on: {bad[:10]}")

    def test_caret_is_a_prerelease_suffix(self):
        # the ^ handling was simply missing: secureblue ships 18 packages using it,
        # e.g. rdma-core-61.1^20260812git975bdaf-1.fc44
        self.assertEqual(S.rpmvercmp("1.0.3^20160216git5e9be27", "1.0.3"), 1)
        self.assertEqual(S.rpmvercmp("1.0.3", "1.0.3^20160216git5e9be27"), -1)
        self.assertEqual(S.rpmvercmp("1.0.3^20160216git", "1.0.3.1"), -1)
        self.assertEqual(S.rpmvercmp("61.1^20260812", "61.1^20260901"), -1)

    def test_numeric_segment_beats_alpha(self):
        self.assertEqual(S.rpmvercmp("1.0.1", "1.0.a"), 1)
        self.assertEqual(S.rpmvercmp("1.0.a", "1.0.1"), -1)

    def test_tilde_sorts_before_everything(self):
        self.assertEqual(S.rpmvercmp("1.0~rc1", "1.0"), -1)
        self.assertEqual(S.rpmvercmp("1.0", "1.0~rc1"), 1)


class TestEvrCmp(unittest.TestCase):
    def test_release_only_bump_is_an_upgrade(self):
        self.assertLess(S.evr_cmp(NSS_OLD, NSS_NEW), 0)
        self.assertGreater(S.evr_cmp(NSS_NEW, NSS_OLD), 0)

    def test_epoch_dominates(self):
        self.assertGreater(S.evr_cmp(pkg("nss", "4.39.0-1.fc44", "nss", epoch="2"),
                                     pkg("nss", "9.0-1.fc44", "nss", epoch="1")), 0)
        # an int epoch must not crash the comparison (real data is a string, but
        # rpmvercmp itself only accepts str)
        self.assertGreater(S.evr_cmp(dict(NSS_OLD, epoch=2), NSS_NEW), 0)

    def test_226_live_epoch_packages_compare(self):
        # sanity: the current image has 226 packages with a non-zero epoch
        self.assertGreater(S.evr_cmp(pkg("a", "1-2.fc44", epoch="1"),
                                     pkg("a", "9-9.fc44", epoch="0")), 0)


# --------------------------------------------------------------------------- #
# A1 / A3 - classify_change must not count other people's errata
# --------------------------------------------------------------------------- #
class TestClassifyChange(unittest.TestCase):
    def test_old_build_erratum_does_not_escalate(self):
        info = S.classify_change(NSS_OLD, NSS_NEW, "F44", FakeBodhi(NSS_UPDATES))
        self.assertFalse(info["security"],
                         "an erratum for the OLD nvr must not make this update security")
        self.assertEqual(info["sev_rank"], 0)
        self.assertEqual([a["alias"] for a in info["already_had"]],
                         ["FEDORA-2026-42a3a95e62"])
        self.assertEqual(info["aliases"], ["FEDORA-2026-243a820a1c"])
        self.assertEqual(info["cves"], [], "the old build's CVE is not this update's CVE")

    def test_unpushed_erratum_is_reported_but_not_counted(self):
        # live example: ffmpeg matched FEDORA-2026-bcaf0ddb2a with status=unpushed
        upd = {"ffmpeg": [{"alias": "FEDORA-2026-bcaf0ddb2a", "type": "security",
                           "severity": "important", "status": "unpushed",
                           "nvrs": ["ffmpeg-7.1-3.fc44"], "notes": "CVE-2026-9999",
                           "bugs": [], "title": "", "cves": []}]}
        info = S.classify_change(None, pkg("ffmpeg", "7.1-3.fc44"), "F44", FakeBodhi(upd))
        self.assertFalse(info["security"])
        self.assertEqual(info["sev_rank"], 0)
        self.assertEqual([a["alias"] for a in info["not_pushed"]],
                         ["FEDORA-2026-bcaf0ddb2a"])
        self.assertTrue(any("not counted" in w for w in info["why"]))

    def test_pushed_security_erratum_does_escalate(self):
        upd = {"kernel": [{"alias": "FEDORA-2026-aaaaaaaaaa", "type": "security",
                           "severity": "important", "status": "stable",
                           "nvrs": ["kernel-7.2.5-200.fc44"], "notes": "",
                           "bugs": [], "title": "", "cves": []}]}
        info = S.classify_change(None, pkg("kernel", "7.2.5-200.fc44"), "F44",
                                 FakeBodhi(upd))
        self.assertTrue(info["security"])
        self.assertEqual(info["sev_rank"], S.SEV_RANK["important"])

    def test_cve_found_only_in_bug_title(self):
        # B1: Bodhi's update objects carry no usable `cves` key; for
        # FEDORA-2026-d3e275d525 the only place CVE-2026-2673 appears is bugs[].title
        upd = {"sudo": [{"alias": "FEDORA-2026-d3e275d525", "type": "security",
                         "severity": "moderate", "status": "stable",
                         "nvrs": ["sudo-1.9.17-2.fc44"], "notes": "Fix a crash",
                         "bugs": [{"title": "sudo: CVE-2026-2673 out-of-bounds read"}],
                         "title": "", "cves": []}]}
        info = S.classify_change(None, pkg("sudo", "1.9.17-2.fc44"), "F44",
                                 FakeBodhi(upd))
        self.assertIn("CVE-2026-2673", info["cves"])

    def test_secureblue_local_release_is_matched(self):
        # secureblue rebuilds carry no Fedora dist tag at all
        cands = set(S.nvr_candidates(pkg("trivalent", "153.0.8010.47-447379")))
        self.assertIn("trivalent-153.0.8010.47-447379", cands)
        cands = set(S.nvr_candidates(pkg("kernel", "7.2.5-200.secureblue.1.fc44")))
        self.assertIn("kernel-7.2.5-200.secureblue.1.fc44", cands)


# --------------------------------------------------------------------------- #
# A4 - never claim "rebuilt with the same version" without reading versions
# --------------------------------------------------------------------------- #
class TestCrosscheckChunks(unittest.TestCase):
    LDIFF = {"changed_chunks": [
        {"components": ["rpm/kernel"], "size": 100},
        {"components": ["rpm/linux-firmware"], "size": 200},
        {"components": ["bigfiles/initramfs.img"], "size": 50},
    ]}

    def test_versions_unknown_makes_no_claim(self):
        xc = S.crosscheck_chunks(self.LDIFF, {"changed": []}, versions_known=False)
        self.assertEqual(xc["silent_rebuilds"], [])
        self.assertFalse(xc["versions_known"])
        # non-package chunks are still reported - that needs no version data
        self.assertEqual([c["components"] for c in xc["non_package_chunks"]],
                         [["bigfiles/initramfs.img"]])

    def test_versions_known_still_detects_silent_rebuilds(self):
        diff = {"changed": [{"name": "kernel", "src": "kernel"}]}
        xc = S.crosscheck_chunks(self.LDIFF, diff, versions_known=True)
        self.assertTrue(xc["versions_known"])
        self.assertEqual([n for n, _ in xc["silent_rebuilds"]], ["linux-firmware"])

    def test_multi_component_chunk_is_not_attributed(self):
        # in a bundled chunk a changed digest may come from any member
        ld = {"changed_chunks": [{"components": ["rpm/a", "rpm/b"], "size": 10}]}
        xc = S.crosscheck_chunks(ld, {"changed": []}, versions_known=True)
        self.assertEqual(xc["silent_rebuilds"], [])


# --------------------------------------------------------------------------- #
# A5 - argument orientation
# --------------------------------------------------------------------------- #
class TestOrient(unittest.TestCase):
    OLD = {"created": "2026-09-16T11:59:43Z", "ref": "20260916"}
    NEW = {"created": "2026-09-17T12:08:19Z", "ref": "latest"}

    def test_newest_first_is_swapped(self):
        a, b, swapped = S.orient(self.NEW, self.OLD)
        self.assertTrue(swapped)
        self.assertEqual((a["ref"], b["ref"]), ("20260916", "latest"))

    def test_correct_order_is_left_alone(self):
        a, b, swapped = S.orient(self.OLD, self.NEW)
        self.assertFalse(swapped)
        self.assertEqual((a["ref"], b["ref"]), ("20260916", "latest"))

    def test_keep_order_disables_the_swap(self):
        a, b, swapped = S.orient(self.NEW, self.OLD, keep_order=True)
        self.assertFalse(swapped)
        self.assertEqual(a["ref"], "latest")

    def test_missing_created_never_guesses(self):
        a, b, swapped = S.orient(self.NEW, {"ref": "x"})
        self.assertFalse(swapped)


# --------------------------------------------------------------------------- #
# A2 - history rows must expose the platform digest
# --------------------------------------------------------------------------- #
class TestBuildHistoryDigestSpace(unittest.TestCase):
    """`build_history` keys rows by the *index* digest. A caller comparing that to
    `resolve()["digest"]` (the platform digest) never matches - which is how a
    first run ended up diffing an image against itself and reporting no-change."""

    INDEX = "sha256:" + "a" * 64
    PLATFORM = "sha256:" + "b" * 64

    def _rows(self):
        class FakeReg:
            host, repo, timeout, arch = "ghcr.io", "secureblue/x", 30, "amd64"

            def _token(self):
                return "t"

        reg = FakeReg()
        calls = {"n": 0}

        def fake_resolve(r, ref, light=False):
            calls["n"] += 1
            return {"is_index": True, "index_digest": self.INDEX, "digest": self.PLATFORM,
                    "created": "2026-09-17T12:08:19Z", "layers": [], "total_size": 0,
                    "annotations": {"org.opencontainers.image.version": "44.20260917.0"},
                    "ref": ref}

        orig = S.resolve
        S.resolve = fake_resolve
        try:
            # .sig tags resolve to the signed image; a distinct index digest is what
            # makes the row appear at all
            rows = S.build_history(reg, scan=0, days=0, to="latest")
        finally:
            S.resolve = orig
        return rows

    def test_rows_carry_both_digests_and_never_collide(self):
        rows = self._rows()
        self.assertTrue(rows)
        r = rows[0]
        self.assertEqual(r["digest"], self.INDEX)
        self.assertEqual(r["platform_digest"], self.PLATFORM)
        self.assertNotEqual(r["digest"], r["platform_digest"],
                            "the two digest spaces must stay distinguishable")


# --------------------------------------------------------------------------- #
# verdict_of - the no-change claim needs real evidence
# --------------------------------------------------------------------------- #
class TestVerdictNoChange(unittest.TestCase):
    LDIFF = {"chunks_changed": 0, "chunks_reused": 128, "download_bytes": 0,
             "total_size_b": 1 << 30, "changed_chunks": [], "chunks_a": 128,
             "chunks_b": 128, "changed_packages_from_chunks": []}
    XC = {"silent_rebuilds": [], "non_package_chunks": [], "non_package_bytes": 0}

    def _verdict(self, meta):
        return S.verdict_of({"added": [], "removed": [], "downgrades": [],
                             "changed": [], "count_a": 0, "count_b": 0},
                            self.LDIFF, meta, self.XC)

    def test_identical_commit_is_called_byte_identical(self):
        v = self._verdict({"inputhash_a": "x", "inputhash_b": "x",
                           "commit_a": "c1", "commit_b": "c1"})
        self.assertEqual(v["level"], "no-change")
        self.assertTrue(v["same_commit"])
        self.assertIn("byte-identical", v["headline"])

    def test_inputhash_alone_is_weaker_evidence(self):
        v = self._verdict({"inputhash_a": "x", "inputhash_b": "x",
                           "commit_a": "c1", "commit_b": "c2"})
        self.assertEqual(v["level"], "no-change")
        self.assertFalse(v["same_commit"])
        self.assertIn("ostree commit differs", v["headline"])

    def test_any_change_blocks_the_no_change_verdict(self):
        ld = dict(self.LDIFF, changed_chunks=[{"components": ["rpm/a"], "size": 1}])
        v = S.verdict_of({"added": [], "removed": [], "downgrades": [],
                          "changed": [{"name": "a", "src": "a", "dir": "upgrade",
                                       "old": pkg("a", "1-1"), "new": pkg("a", "1-2"),
                                       "cls": {"security": True, "cves": [],
                                               "aliases": [], "why": [],
                                               "sev_rank": 0, "already_had": [],
                                               "not_pushed": []}}],
                          "count_a": 1, "count_b": 1}, ld,
                         {"inputhash_a": "x", "inputhash_b": "x",
                          "commit_a": "c1", "commit_b": "c1"}, self.XC)
        self.assertNotEqual(v["level"], "no-change")


# --------------------------------------------------------------------------- #
# B1 - Bodhi cache must not be trusted blindly
# --------------------------------------------------------------------------- #
class TestBodhiCache(unittest.TestCase):
    def test_corrupt_cache_is_discarded_not_crashed(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("kernel-F44")            # the class's own path helper
            with open(cf, "w") as fh:
                fh.write("{ this is not json")
            # the guard must notice, unlink and report None - not raise
            self.assertIsNone(b._read_cache(cf))
            self.assertFalse(os.path.exists(cf), "corrupt cache file was not removed")

    def test_cache_holding_the_wrong_json_shape_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("glibc-F44")
            with open(cf, "w") as fh:
                json.dump({"not": "a list"}, fh)   # valid JSON, wrong type
            self.assertIsNone(b._read_cache(cf))

    def test_valid_cache_is_used(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("rpm-F44")
            payload = [{"alias": "FEDORA-2026-1", "type": "bugfix", "status": "stable",
                        "severity": "unspecified", "nvrs": ["rpm-4.20-1.fc44"],
                        "notes": "", "bugs": [], "title": "", "cves": []}]
            with open(cf, "w") as fh:
                json.dump(payload, fh)
            self.assertEqual(b._read_cache(cf), payload)


# --------------------------------------------------------------------------- #
# C1 - backlog coverage must be reported
# --------------------------------------------------------------------------- #
class TestBacklogCoverage(unittest.TestCase):
    def test_coverage_reports_truncation_and_pool_gaps(self):
        pkgs = {n: pkg(n, "1-1.fc44", n) for n in ("kernel", "glibc", "openssl")}
        cov_line = S.coverage_line({"candidates": 9, "checked": 3, "skipped": 6,
                                    "skipped_names": ["a", "b", "c", "d", "e", "f"],
                                    "pool_missing": ["nginx", "bind"]})
        self.assertIn("3 of 9", cov_line)
        self.assertIn("6 were cut off", cov_line)
        self.assertIn("2 BACKLOG_POOL entries", cov_line)
        self.assertEqual(len(pkgs), 3)

    def test_backlog_returns_rows_and_coverage(self):
        pkgs = {"kernel": pkg("kernel", "7.2.4-100.fc44", "kernel")}
        upd = {"kernel": [{"alias": "FEDORA-2026-ffffffff", "type": "security",
                           "severity": "important", "status": "stable",
                           "nvrs": ["kernel-7.2.5-200.fc44"], "notes": "",
                           "bugs": [], "title": "", "cves": []}]}
        rows, cov = S.security_backlog(pkgs, "F44", FakeBodhi(upd), limit=10)
        self.assertEqual([r["name"] for r in rows], ["kernel"])
        self.assertEqual(cov["checked"], 1)
        self.assertIn("nginx", cov["pool_missing"])


# --------------------------------------------------------------------------- #
# E3 - atomic state write / E5 - derived Fedora release
# --------------------------------------------------------------------------- #
class TestRobustness(unittest.TestCase):
    def test_atomic_write_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "state.json")
            S._atomic_write_json(p, {"a": 1})
            with open(p) as fh:
                self.assertEqual(json.load(fh), {"a": 1})
            self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])

    def test_fedora_release_is_not_hardcoded(self):
        pkgs = {"a": pkg("a", "1-1.fc45"), "b": pkg("b", "2-3.fc45"), "c": pkg("c", "1-1.fc44")}
        self.assertEqual(S.fedora_release(pkgs), "F45")
        self.assertEqual(S.fedora_release({}, "44.20260917.0"), "F44")
        self.assertEqual(S.fedora_release({}, ""), "")

    def test_pseudo_packages_are_listed_for_filtering(self):
        self.assertIn("gpg-pubkey", S.PSEUDO_PACKAGES)


# --------------------------------------------------------------------------- #
# D - dead code must stay deleted
# --------------------------------------------------------------------------- #
class TestDeadCodeRemoved(unittest.TestCase):
    def test_removed_names_are_gone(self):
        for name in ("chunk_map", "SHATAG_RE", "BUILD_NOISE", "INT_TAGS",
                     "_ver_split"):
            self.assertFalse(hasattr(S, name), f"{name} came back")

    def test_rpmtag_1006_is_not_buildhost(self):
        # RPMTAG_BUILDTIME is 1006; calling it "buildhost" silently mislabels data
        self.assertNotIn(1006, S.RPMTAG)
        self.assertEqual(S.RPMTAG[1007], "buildhost")

    def test_group_by_src_has_no_dead_field(self):
        g = S.group_by_src([{"name": "a", "src": "a", "dir": "upgrade",
                             "old": pkg("a", "1-1"), "new": pkg("a", "1-2"),
                             "cls": {"security": False, "cves": [], "aliases": [],
                                     "why": [], "sev_rank": 0, "already_had": [],
                                     "not_pushed": []}}])[0]
        self.assertNotIn("same_evr", g)
        self.assertIn("already_had", g)
        self.assertIn("unreleased", g)


# --------------------------------------------------------------------------- #
# B4/B5 - download caps must be enforced while streaming
# --------------------------------------------------------------------------- #
class TestCaps(unittest.TestCase):
    def test_capped_reader_aborts_over_budget(self):
        class R:
            def __init__(self, data):
                self.b = io.BytesIO(data)

            def read(self, n=-1):
                return self.b.read(n)

        cr = S._CappedReader(R(b"x" * 500), 100, "test")
        with self.assertRaises(SystemExit):
            cr.read(1000)

    def test_capped_reader_peek_does_not_consume(self):
        class R:
            def __init__(self, data):
                self.b = io.BytesIO(data)

            def read(self, n=-1):
                return self.b.read(n)

        cr = S._CappedReader(R(b"\x1f\x8bhello"), 1000, "test")
        self.assertEqual(cr.peek(2), b"\x1f\x8b")
        self.assertEqual(cr.read(7), b"\x1f\x8bhello")


if __name__ == "__main__":
    unittest.main(verbosity=2)
