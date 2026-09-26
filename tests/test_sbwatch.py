#!/usr/bin/env python3
"""Offline regression tests for sbwatch.py.

No network, no registry, no `rpm` module - everything here runs against the real
behaviour of the shipped code with in-memory fixtures. Run with:

    python3 tests/test_sbwatch.py            # or: python3 -m unittest discover -s tests

Each group is named after the finding it locks down, so a failure points straight
at the regression it guards:
  A1/A3  classify_change: errata for the OLD build, and unpushed errata
  A2     build_history rows must carry the platform digest (list_tags is stubbed -
         this suite makes NO network calls at all)
  A4     crosscheck_chunks must not invent "same version" claims
  A5     orient(): A must be the older build
  A6     rpmvercmp against rpm's own 91 upstream test vectors
  A7     nvr_candidates: source-name spellings (shim/webkitgtk/krb5/...) and the
         stripped .secureblue.N marker must both be offered to Bodhi matching
  B1     Bodhi cache poisoning / CVEs that only live in bugs[].title
  C1     backlog coverage must be reported; pool entries must be real source names
  C2     backlog matching: source-NVR builds, epoch blindness, release marker
  D      dead code must stay dead (incl. Bodhi._read_cache, Registry.__enter__, ICON)
  E3     state writes are atomic
  E6     pkg_diff: epoch-only changes must be visible
  E7     pick_tar_member: largest match wins, tar order must not matter
  I      advisory attachment: an erratum matched only after stripping
         `.secureblue.N` is reported but never drives the notification prediction;
         advisories on *added* packages do
  J      manifest-only (--exact 0) runs answer `unknown`, never a recommendation;
         level_basis is machine-readable; no-change keeps its late annotations
  K      silent/fatal failures: tag probes, backlog severity order, null Bodhi
         nvr, coverage_line, dir-less change entries, missing kernel annotation,
         multilib collisions, read_header stats, atomic report writes
  L      workflow: every action pinned to a SHA, cosign.pub vendored + hashed,
         write permissions scoped, an inconclusive run is not green
"""
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest

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


class _FakeResp:
    """Minimal urlopen() return value."""

    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


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

    def test_epoch_string_and_int_forms_both_compare(self):
        # sanity on the comparison itself (the "226 live epoch packages" figure
        # from the image audit is context, not something this fixture can test -
        # the old name claimed otherwise): epoch dominates version, and a
        # hand-built int epoch must not crash the string-based rpmvercmp
        self.assertGreater(S.evr_cmp(pkg("a", "1-2.fc44", epoch="1"),
                                     pkg("a", "9-9.fc44", epoch="0")), 0)


# --------------------------------------------------------------------------- #
# pkg_diff - an epoch-only change must be visible
# --------------------------------------------------------------------------- #
class TestPkgDiffEpoch(unittest.TestCase):
    def test_epoch_only_change_is_not_skipped(self):
        # nvr AND evr both exclude the epoch, so the old `x["nvr"] == y["nvr"]`
        # skip made an epoch introduction (0:1.2-3 -> 1:1.2-3) invisible
        pa = {"foo": pkg("foo", "1.2-3.fc44", epoch="0")}
        pb = {"foo": pkg("foo", "1.2-3.fc44", epoch="1")}
        d = S.pkg_diff(pa, pb)
        self.assertEqual([c["name"] for c in d["changed"]], ["foo"])
        self.assertEqual(d["changed"][0]["dir"], "upgrade")

    def test_identical_evr_triple_is_skipped(self):
        pa = {"foo": pkg("foo", "1.2-3.fc44", epoch="1")}
        pb = {"foo": pkg("foo", "1.2-3.fc44", epoch="1")}
        self.assertEqual(S.pkg_diff(pa, pb)["changed"], [])

    def test_epoch_downgrade_is_flagged(self):
        pa = {"foo": pkg("foo", "1.2-3.fc44", epoch="2")}
        pb = {"foo": pkg("foo", "1.2-3.fc44", epoch="1")}
        d = S.pkg_diff(pa, pb)
        self.assertEqual(d["changed"][0]["dir"], "downgrade")


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
        # secureblue's own rebuilds carry no Fedora dist tag at all: the raw NVR
        # is the only candidate and there is nothing to strip
        cands = set(S.nvr_candidates(pkg("trivalent", "153.0.8010.47-447379")))
        self.assertEqual(cands, {"trivalent-153.0.8010.47-447379"})
        # the kernel rebuild's release marker must be stripped to the Fedora
        # spelling - THIS is the candidate that actually matches the erratum
        # (FEDORA-2026-9ce2715225 ships kernel-7.2.5-200.fc44). The old test
        # only asserted the raw NVR, which nvr_candidates returns by
        # construction - a tautology that could never fail.
        cands = set(S.nvr_candidates(pkg("kernel", "7.2.5-200.secureblue.1.fc44")))
        self.assertIn("kernel-7.2.5-200.fc44", cands)
        self.assertIn("kernel-7.2.5-200.secureblue.1.fc44", cands)

    def test_src_level_candidate_for_renamed_binaries(self):
        # Bodhi lists errata builds by SOURCE NVR. 246 of the live image's 1107
        # sources have no same-named binary (shim -> shim-x64/shim-ia32,
        # webkitgtk -> webkit2gtk4.1/webkitgtk6.0, krb5 -> krb5-libs, ...), so
        # binary-only candidates silently missed their errata. The source-name
        # spelling must also be offered.
        cands = set(S.nvr_candidates(pkg("shim-x64", "16.1-5", src="shim")))
        self.assertIn("shim-16.1-5", cands)         # what Bodhi actually lists
        self.assertIn("shim-x64-16.1-5", cands)     # binary spelling kept
        cands = set(S.nvr_candidates(pkg("webkitgtk6.0", "2.50.1-1.fc44", src="webkitgtk")))
        self.assertIn("webkitgtk-2.50.1-1.fc44", cands)
        # ... and the source spelling also gets the secureblue marker stripped
        cands = set(S.nvr_candidates(
            pkg("kernel-core", "7.2.5-200.secureblue.1.fc44", src="kernel")))
        self.assertIn("kernel-7.2.5-200.fc44", cands)
        self.assertIn("kernel-core-7.2.5-200.secureblue.1.fc44", cands)

    def test_shim_erratum_is_classified_security(self):
        # end-to-end through classify_change with the live shim data: Fedora
        # publishes `shim-16.2-1`, the image has shim-x64-16.1-5 (src shim)
        upd = {"shim": [{"alias": "FEDORA-2026-shimshimsh", "type": "security",
                         "severity": "important", "status": "stable",
                         "nvrs": ["shim-16.1-5"], "notes": "", "bugs": [],
                         "title": "", "cves": []}]}
        info = S.classify_change(None, pkg("shim-x64", "16.1-5", src="shim"),
                                 "F44", FakeBodhi(upd))
        self.assertTrue(info["security"],
                        "shim's erratum matches via the source-name candidate")
        self.assertEqual(info["aliases"], ["FEDORA-2026-shimshimsh"])


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
        orig_tags = S.list_tags
        S.resolve = fake_resolve
        # build_history walks the repo's tag list; without this stub the test
        # made four real HTTP requests to ghcr.io (with a fake bearer token) and
        # spent ~9 s in retry backoff - "passing" only because the registry
        # rejected the token. The suite promises to be offline; keep it that way.
        S.list_tags = lambda reg, max_pages=12: [
            "sha256-" + self.INDEX.split(":")[1] + ".sig",
            "sha256-" + "c" * 64 + ".sig",        # dangling sig: resolves to INDEX too
            "20260917", "latest-uki",             # non-sig tags must be ignored
        ]
        try:
            # .sig tags resolve to the signed image; a distinct index digest is what
            # makes the row appear at all
            rows = S.build_history(reg, scan=0, days=0, to="latest")
        finally:
            S.resolve = orig
            S.list_tags = orig_tags
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

    def test_no_change_rests_on_the_package_set_not_the_annotations(self):
        """`ostree.commit` and `rpmostree.inputhash` are inherited from the Fedora
        base image, so an identical commit is NOT evidence of a byte-identical
        tree.  Measured: secureblue 98613c9b784b and 82baf9855818 are distinct
        images with 20 of 128 layers differing and homebrew 7.0.2-26091605 ->
        7.0.6-26092310, yet share ostree.commit 4df81387..., inputhash
        4fde5b5a8c4f..., ostree.linux and final-diffid.  The verdict must be
        justified by the rpmdb, so the headline must not claim byte-identity."""
        v = self._verdict({"inputhash_a": "x", "inputhash_b": "x",
                           "commit_a": "c1", "commit_b": "c1"})
        self.assertEqual(v["level"], "no-change")
        self.assertTrue(v["same_commit"])
        self.assertIn("no package changed in the rpmdb", v["headline"])
        self.assertNotIn("byte-identical", v["headline"])
        self.assertNotIn("byte-identical", v["headline_zh"])

    def test_differing_commit_does_not_weaken_an_empty_package_set(self):
        """The commit annotation carries no information about this build either way,
        so it must not change the wording or the level."""
        v = self._verdict({"inputhash_a": "x", "inputhash_b": "x",
                           "commit_a": "c1", "commit_b": "c2"})
        self.assertEqual(v["level"], "no-change")
        self.assertFalse(v["same_commit"])
        self.assertIn("no package changed in the rpmdb", v["headline"])
        self.assertNotIn("ostree commit differs", v["headline"])

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
            self.assertIsNone(b._read_cache_entry(cf))
            self.assertFalse(os.path.exists(cf), "corrupt cache file was not removed")

    def test_cache_holding_the_wrong_json_shape_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("glibc-F44")
            with open(cf, "w") as fh:
                json.dump({"not": "a list"}, fh)   # valid JSON, wrong type
            self.assertIsNone(b._read_cache_entry(cf))

    def test_legacy_list_cache_still_readable(self):
        # caches written before pagination existed are a bare list
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("rpm-F44")
            payload = [{"alias": "FEDORA-2026-1", "type": "bugfix", "status": "stable",
                        "severity": "unspecified", "nvrs": ["rpm-4.20-1.fc44"],
                        "notes": "", "bugs": [], "title": "", "cves": []}]
            with open(cf, "w") as fh:
                json.dump(payload, fh)
            ent = b._read_cache_entry(cf)
            self.assertEqual(ent["updates"], payload)
            self.assertFalse(ent["truncated"])
            self.assertIsNone(ent["total"])
            self.assertEqual(b.updates_for_src("rpm", "F44"), payload)

    def test_new_cache_shape_roundtrips(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("rpm-F44")
            with open(cf, "w") as fh:
                json.dump({"total": 1, "truncated": False,
                           "updates": [{"alias": "FEDORA-2026-1"}]}, fh)
            self.assertEqual(b.updates_for_src("rpm", "F44"),
                             [{"alias": "FEDORA-2026-1"}])
            self.assertEqual(b.truncated_src, set())

    def test_truncated_cache_marks_the_source(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("kernel-F44")
            with open(cf, "w") as fh:
                json.dump({"total": 999, "truncated": True, "updates": []}, fh)
            b.updates_for_src("kernel", "F44")
            self.assertEqual(b.truncated_src, {"kernel"})


class TestBodhiPagination(unittest.TestCase):
    """Bodhi paginates; reading only page 1 silently dropped 27 of the F44
    kernel's 127 errata. Walk every page, and say so when the bound is hit."""

    class FakeHTTP:
        """urlopen stand-in serving N fake updates across pages of 100."""

        def __init__(self, total):
            self.total, self.calls = total, 0

        def __call__(self, url, timeout=None):
            import urllib.parse as up
            q = dict(up.parse_qsl(up.urlparse(url).query))
            page, rpp = int(q["page"]), int(q["rows_per_page"])
            self.calls += 1
            start = (page - 1) * rpp
            ups = [{"alias": f"FEDORA-{i}", "type": "bugfix", "severity": "unspecified",
                    "status": "stable", "title": "", "notes": "", "bugs": [],
                    "builds": [{"nvr": f"kernel-1.{i}-1.fc44"}]}
                   for i in range(start, min(start + rpp, self.total))]
            body = json.dumps({"total": self.total, "updates": ups}).encode()
            return _FakeResp(body)

    def _run(self, total, max_pages=None):
        b = S.Bodhi(cache_dir=None, max_calls=99, sleep=0)
        orig_open, orig_max = S.urllib.request.urlopen, S.MAX_BODHI_PAGES
        fake = self.FakeHTTP(total)
        S.urllib.request.urlopen = fake
        if max_pages:
            S.MAX_BODHI_PAGES = max_pages
        try:
            ups = b.updates_for_src("kernel", "F44")
        finally:
            S.urllib.request.urlopen = orig_open
            S.MAX_BODHI_PAGES = orig_max
        return ups, b, fake

    def test_reads_beyond_the_first_page(self):
        ups, b, fake = self._run(127)          # the real F44 kernel count
        self.assertEqual(len(ups), 127)
        self.assertEqual(fake.calls, 2)
        self.assertEqual(b.truncated_src, set())

    def test_single_page_package_costs_one_request(self):
        ups, b, fake = self._run(20)
        self.assertEqual(len(ups), 20)
        self.assertEqual(fake.calls, 1)

    def test_hitting_the_page_bound_is_reported_not_hidden(self):
        ups, b, fake = self._run(5000, max_pages=2)
        self.assertEqual(len(ups), 200)
        self.assertEqual(b.truncated_src, {"kernel"})


# --------------------------------------------------------------------------- #
# C1 - backlog coverage must be reported
# --------------------------------------------------------------------------- #
class TestBacklogCoverage(unittest.TestCase):
    def test_coverage_reports_truncation_and_pool_gaps(self):
        cov_line = S.coverage_line({"candidates": 9, "checked": 3, "skipped": 6,
                                    "skipped_names": ["a", "b", "c", "d", "e", "f"],
                                    "pool_missing": ["nginx", "bind"]})
        self.assertIn("3 of 9", cov_line)
        self.assertIn("6 were cut off", cov_line)
        self.assertIn("2 BACKLOG_POOL entries", cov_line)

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
        # fixed pool entries must now BE in the pool (typos silently shrank the
        # audit before: wireless-regdog, giolang-github, veritysetup, ...)
        for good in ("wireless-regdb", "cryptsetup", "linux-firmware", "python3",
                     "xorg-x11-server-Xwayland", "polkit-qt6-1"):
            self.assertIn(good, S.BACKLOG_POOL)
        for bad in ("wireless-regdog", "giolang-github", "veritysetup",
                    "amd-gpu-firmware", "trivalent-native",
                    "trivalent-binary-packaging", "polkit-qt"):
            self.assertNotIn(bad, S.BACKLOG_POOL)
            self.assertNotIn(bad, S.IMPORTANT_SRC)


class TestBacklogMatching(unittest.TestCase):
    """Errata builds are SOURCE NVRs without epoch; the image side has binary
    names, sometimes an epoch, and sometimes secureblue's release marker. All
    three mismatches used to make 'behind' undetectable."""

    @staticmethod
    def _upd(nvr, alias="FEDORA-2026-backlog01"):
        return [{"alias": alias, "type": "security", "severity": "important",
                 "status": "stable", "nvrs": [nvr], "notes": "", "bugs": [],
                 "title": "", "cves": []}]

    def test_src_name_binary_matches(self):
        # shim ships as shim-x64/shim-ia32; Bodhi lists `shim-16.2-1`
        pkgs = {"shim-x64": pkg("shim-x64", "16.1-5", src="shim")}
        rows, _ = S.security_backlog(pkgs, "F44",
                                     FakeBodhi({"shim": self._upd("shim-16.2-1")}),
                                     limit=10)
        self.assertEqual([r["name"] for r in rows], ["shim-x64"])
        self.assertEqual(rows[0]["want"], "16.2-1")

    def test_epoch_package_can_be_behind(self):
        # live example: cups has epoch 1 in the image; Bodhi NVRs carry no epoch,
        # so the old evr_cmp made cups permanently "newer" than every update
        pkgs = {"cups": pkg("cups", "2.4.19-3.fc44", src="cups", epoch="1")}
        rows, _ = S.security_backlog(
            pkgs, "F44",
            FakeBodhi({"cups": self._upd("cups-2.4.20-1.fc44")}), limit=10)
        self.assertEqual([r["name"] for r in rows], ["cups"])

    def test_secureblue_release_marker_ignored(self):
        # the image's kernel-7.2.5-200.secureblue.1.fc44 IS secureblue's rebuild
        # of Fedora's kernel-7.2.5-200.fc44: with the marker stripped the two are
        # equal -> not behind. A genuinely newer Fedora build is still behind.
        pkgs = {"kernel": pkg("kernel", "7.2.5-200.secureblue.1.fc44", src="kernel")}
        rows, _ = S.security_backlog(
            pkgs, "F44",
            FakeBodhi({"kernel": self._upd("kernel-7.2.5-200.fc44")}), limit=10)
        self.assertEqual(rows, [], "a rebuild of the same Fedora build is not 'behind'")
        self.assertTrue(S._is_behind(pkgs["kernel"], "7.2.5", "201.fc44"))
        self.assertFalse(S._is_behind(pkgs["kernel"], "7.2.5", "200.fc44"))
        self.assertFalse(S._is_behind(pkgs["kernel"], "7.2.4", "300.fc44"))

    def test_not_behind_stays_out(self):
        pkgs = {"kernel": pkg("kernel", "7.2.6-200.secureblue.1.fc44", src="kernel")}
        rows, _ = S.security_backlog(
            pkgs, "F44",
            FakeBodhi({"kernel": self._upd("kernel-7.2.5-200.fc44")}), limit=10)
        self.assertEqual(rows, [])

    def test_python_versioned_src_is_pool_member(self):
        # F44's interpreter source is python3.14; the pool lists the stable stem
        pkgs = {"python3-libs": pkg("python3-libs", "3.14.7-1.fc44", src="python3.14")}
        rows, cov = S.security_backlog(
            pkgs, "F44",
            FakeBodhi({"python3.14": self._upd("python3.14-3.14.8-1.fc44")}), limit=10)
        self.assertEqual([r["name"] for r in rows], ["python3-libs"])
        self.assertNotIn("python3", cov["pool_missing"],
                         "python3.14 must satisfy the pool's `python3` entry")
        self.assertTrue(S._src_matches_pool("python3.14", S.BACKLOG_POOL))
        self.assertTrue(S._src_matches_pool("python3.14", S.IMPORTANT_SRC))
        self.assertFalse(S._src_matches_pool("python3x", S.BACKLOG_POOL))


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

    def test_read_cache_is_gone(self):
        # Bodhi._read_cache had no production caller left (only tests used it);
        # its docstring claimed a contract for callers that no longer existed.
        self.assertFalse(hasattr(S.Bodhi, "_read_cache"))

    def test_registry_context_manager_is_gone(self):
        # nothing ever used `with Registry(...)` - cleanup runs via atexit in
        # _registry(); the dead __enter__/__exit__ pair only suggested otherwise
        self.assertFalse(hasattr(S.Registry, "__enter__"))
        self.assertFalse(hasattr(S.Registry, "__exit__"))

    def test_rpmtag_1006_is_not_buildhost(self):
        # RPMTAG_BUILDTIME is 1006; calling it "buildhost" silently mislabels data
        self.assertNotIn(1006, S.RPMTAG)
        self.assertEqual(S.RPMTAG[1007], "buildhost")

    def test_merged_icon_dict_is_gone(self):
        # ICON was a merged-bilingual fallback that ICON_ZH/ICON_EN made unreachable
        self.assertFalse(hasattr(S, "ICON"))

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


# --------------------------------------------------------------------------- #
# pick_tar_member - the live rpmdb chunk carries TWO `rpmdb.sqlite` entries
# (the real ~92 MiB db under usr/lib/sysimage/rpm-ostree-base-db/ and a 0-byte
# placeholder at usr/share/rpm/rpmdb.sqlite); selection must not depend on the
# order the tar happens to list them in.
# --------------------------------------------------------------------------- #
class TestPickTarMember(unittest.TestCase):
    def _tar(self, members):
        """members = [(name, bytes|None-for-symlink-target)] in write order."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, payload in members:
                ti = tarfile.TarInfo(name)
                if payload is None:
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite"
                    tf.addfile(ti)
                else:
                    ti.size = len(payload)
                    tf.addfile(ti, io.BytesIO(payload))
        buf.seek(0)
        return tarfile.open(fileobj=buf)

    def test_prefers_largest_match_regardless_of_order(self):
        real = b"SQLite format 3\0" + b"x" * 512
        real_path = "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite"
        stub = ("usr/share/rpm/rpmdb.sqlite", b"")
        for real_first in (True, False):
            with self.subTest(real_first=real_first):
                members = ([(real_path, real), stub] if real_first
                           else [stub, (real_path, real)])
                tf = self._tar(members)
                m, sym = S.pick_tar_member(tf, "rpmdb.sqlite")
                tf.close()
                self.assertIsNotNone(m)
                self.assertEqual(m.size, len(real))
                self.assertEqual(m.name, real_path)
                self.assertIsNone(sym)

    def test_symlink_target_reported_when_no_regular_file_matches(self):
        tf = self._tar([("usr/share/rpm/rpmdb.sqlite", None)])
        m, sym = S.pick_tar_member(tf, "rpmdb.sqlite")
        tf.close()
        self.assertIsNone(m)
        self.assertEqual(sym, "usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite")

    def test_member_cap_is_enforced_while_scanning(self):
        tf = self._tar([(f"f{i}", b"x") for i in range(5)])
        orig = S.MAX_TAR_MEMBERS
        S.MAX_TAR_MEMBERS = 3
        try:
            with self.assertRaises(SystemExit):
                S.pick_tar_member(tf, "f")
        finally:
            S.MAX_TAR_MEMBERS = orig
            tf.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)


# --------------------------------------------------------------------------- #
# F - secureblue's own notification rule must be reproduced, not approximated
#
# Source of truth: secureblue/secureblue
#   files/system/desktop/usr/libexec/secureblue/security-update-notification
#     MAJOR : 'trivalent' in .rpm-diff.upgraded[][1]  OR  max advisory sev == critical
#     NORMAL: 'kernel'    in .rpm-diff.upgraded[][1]  OR  max advisory sev in
#                                                     {important, unknown}
# Every test below is anchored to a measured fact about the live system, noted
# inline, so a failure says which observation stopped holding.
# --------------------------------------------------------------------------- #
LD_FIX = {"download_bytes": 250 * 1024 * 1024, "total_size_b": 4 * 1024 ** 3,
          "changed_chunks": [], "reused_chunks": [], "changed_packages_from_chunks": []}
# Measured: 44.20260922.0 and 44.20260923.0 carry the SAME rpmostree.inputhash
# (4fde5b5a8c4ff655...) AND the SAME ostree.linux (7.2.6-200.fc44.x86_64), while
# kernel/kernel-core/kernel-modules{,-core,-extra}, hardened_malloc and trivalent
# all moved.
META_IDENTICAL = {"kernel_a": "7.2.6-200.fc44.x86_64", "kernel_b": "7.2.6-200.fc44.x86_64",
                  "inputhash_a": "4fde5b5a8c4ff655", "inputhash_b": "4fde5b5a8c4ff655",
                  "commit_a": "7a67d1be315f2184", "commit_b": "4df81387b6a0c38c"}
BSTATE = {"failed": 0, "skipped": 0, "truncated": []}


def _verdict(pa, pb, meta=META_IDENTICAL):
    d = S.pkg_diff(pa, pb)
    src_of = {n: p["src"] for n, p in pb.items()}
    return S.verdict_of(d, LD_FIX, meta, S.crosscheck_chunks(LD_FIX, d, src_of), [], BSTATE)


class TestRpmOstreeSeverityVocabulary(unittest.TestCase):
    def test_only_rhel_spellings_rank(self):
        """rpm-ostree str2severity() knows LOW/MODERATE/IMPORTANT/CRITICAL only."""
        for word, want in (("low", 1), ("moderate", 2), ("important", 3), ("critical", 4),
                           ("LOW", 1), ("Critical", 4)):
            self.assertEqual(S.rpmostree_str2severity(word), want, word)

    def test_raw_bodhi_words_are_invisible_to_rpmostree(self):
        """Bodhi's UpdateSeverity is unspecified/urgent/high/medium/low - none of
        which str2severity() recognises.  That is exactly why the severity must be
        run through bodhi_severity_as_updateinfo() first: Bodhi translates its own
        vocabulary to RHEL spellings when writing the updateinfo <severity> child
        element, and THAT string is what rpm-ostree sees.  Feeding the raw API
        word would under-predict 'urgent' (really Critical -> MAJOR) and
        over-predict 'medium' (really Moderate -> silent)."""
        for word in ("urgent", "high", "medium", "unspecified", "", None):
            self.assertEqual(S.rpmostree_str2severity(word), 0, word)

    def test_bodhi_words_map_to_rhel_spellings_like_bodhi_itself(self):
        """Mirror of bodhi-server util.severity_updateinfo_str(), including the
        get(value, 'None') fallback for missing/unknown severities."""
        cases = {"unspecified": "None", "low": "Low", "medium": "Moderate",
                 "high": "Important", "urgent": "Critical"}
        for bodhi_word, published in cases.items():
            self.assertEqual(S.bodhi_severity_as_updateinfo(bodhi_word), published, bodhi_word)
        for absent in ("", None, "whatever-bodhi-adds-next"):
            self.assertEqual(S.bodhi_severity_as_updateinfo(absent), "None", absent)

    def test_fedora_publishes_severity_as_child_element(self):
        """Measured on the live mirror 2026-09-24: all 2979 <update> entries in the
        F44 updates repo carry a <severity> CHILD element (None=2326, Low=259,
        Moderate=254, Important=125, Critical=15 - incl. chromium
        FEDORA-2026-f910229c11 issued 2026-09-22) while 0 carry a severity=
        ATTRIBUTE.  libsolv parses the child element (repo_updateinfoxml.c), so
        dnf_advisory_get_severity() returns the real RHEL spelling and 'critical'
        IS reachable - bodhi#2099 closed 2018-01-16.  Full chain, Bodhi word ->
        published spelling -> rpm-ostree integer:"""
        for bodhi_word, want in (("urgent", 4), ("high", 3), ("medium", 2),
                                 ("low", 1), ("unspecified", 0)):
            published = S.bodhi_severity_as_updateinfo(bodhi_word)
            self.assertEqual(S.rpmostree_str2severity(published), want, bodhi_word)
        # a security advisory with no severity at all lands on the 'unknown' arm,
        # which the NORMAL branch acts on - not on 'none'.
        n = S.secureblue_notification(
            {"changed": [{"name": "glibc", "src": "glibc", "dir": "upgrade"}]},
            [{"src": "glibc", "has_security_erratum": True, "erratum_severity": "None"}])
        self.assertEqual(n["max_advisory_severity"], "unknown")
        self.assertEqual(n["level"], "normal")


class TestTrivalentIsMajor(unittest.TestCase):
    def test_trivalent_bump_alone_is_major_and_escalates(self):
        """secureblue fires its critical-urgency popup for ANY trivalent bump.
        Trivalent has no Fedora counterpart, so no Bodhi erratum can ever match -
        the old code parked it in IMPORTANT_SRC and answered `no-change` here."""
        v = _verdict({"trivalent": pkg("trivalent", "153.0.8010.52-447428")},
                     {"trivalent": pkg("trivalent", "154.0.8037.57-447533")})
        n = v["secureblue_notification"]
        self.assertEqual(n["level"], "major")
        self.assertEqual(n["message"], "A major security vulnerability has been patched")
        self.assertTrue(n["trivalent_updated"])
        self.assertEqual(v["level"], "update-now")
        self.assertEqual(v["escalated_by_secureblue_rule"], "skip")

    def test_trivalent_subpackage_name_is_not_enough(self):
        """Upstream matches the binary name literally; a differently-named binary
        from the same source does not trip it."""
        n = S.secureblue_notification(
            {"changed": [{"name": "trivalent-libs", "src": "trivalent", "dir": "upgrade"}]})
        self.assertFalse(n["trivalent_updated"])


class TestKernelDetectionUsesThePackageDiff(unittest.TestCase):
    def test_kernel_seen_despite_identical_ostree_linux(self):
        """The real 20260922 -> 20260923 case: ostree.linux is identical on both
        images, so annotation-based detection reported kernel_changed=False while
        the kernel package really went 7.2.6 -> 7.2.7."""
        pa = {"kernel": pkg("kernel", "7.2.6-200.secureblue.3.fc44"),
              "kernel-core": pkg("kernel-core", "7.2.6-200.secureblue.3.fc44", "kernel")}
        pb = {"kernel": pkg("kernel", "7.2.7-200.secureblue.1.fc44"),
              "kernel-core": pkg("kernel-core", "7.2.7-200.secureblue.1.fc44", "kernel")}
        v = _verdict(pa, pb)
        self.assertTrue(v["kernel_in_diff"])
        self.assertFalse(v["kernel_annotation_changed"])
        self.assertTrue(v["kernel_changed"])
        self.assertEqual(v["secureblue_notification"]["level"], "normal")
        # the reported EVRs must come from the packages, not from a None annotation
        self.assertIn("7.2.7-200.secureblue.1.fc44", v["headline"])

    def test_kernel_downgrade_is_not_an_upgrade(self):
        """rpm-ostree puts downgrades in a separate array the script never reads."""
        n = S.secureblue_notification(
            {"changed": [{"name": "kernel", "src": "kernel", "dir": "downgrade"}]})
        self.assertFalse(n["kernel_updated"])
        self.assertEqual(n["level"], "none")


class TestNoChangeNeedsAnEmptyPackageSet(unittest.TestCase):
    def test_identical_inputhash_with_moved_packages_is_not_no_change(self):
        """inputhash alone is not evidence of a no-op: the measured 20260922/23
        pair shares it while 7 packages moved."""
        v = _verdict({"trivalent": pkg("trivalent", "153.0.8010.52-447428")},
                     {"trivalent": pkg("trivalent", "154.0.8037.57-447533")})
        self.assertNotEqual(v["level"], "no-change")
        self.assertTrue(v["same_inputhash_but_packages_moved"])
        self.assertNotIn("no new content", v["headline"])

    def test_identical_inputhash_and_identical_commit_still_no_change(self):
        pa = {"glibc": pkg("glibc", "2.42-5.fc44")}
        d = S.pkg_diff(pa, dict(pa))
        meta = dict(META_IDENTICAL)
        v = S.verdict_of(d, LD_FIX, meta, S.crosscheck_chunks(LD_FIX, d, {}), [], BSTATE)
        self.assertEqual(v["level"], "no-change")
        self.assertFalse(v["same_inputhash_but_packages_moved"])


class TestDecisionTableMatchesUpstream(unittest.TestCase):
    """Cross-check secureblue_notification against the upstream `case` block,
    transcribed from the shell script. (kernel, trivalent, advisory sev) -> level.

    Severity fixtures use the updateinfo <severity> spelling, the string
    classify_change() stores after bodhi_severity_as_updateinfo() - the jq in
    the shell script sees rpm-ostree's integer for exactly that string."""
    TABLE = [
        # kernel, trivalent, advisory severity int -> expected
        (False, False, None,        "none"),    # nothing relevant moved
        (True,  False, None,        "normal"),  # kernel alone always notifies
        (False, True,  None,        "major"),   # trivalent alone -> critical urgency
        (True,  True,  None,        "major"),   # elif: major wins
        (False, False, 0,           "normal"),  # 0 -> 'unknown' arm (Bodhi 'unspecified' -> 'None')
        (False, False, 1,           "none"),    # low: no notification
        (False, False, 2,           "none"),    # moderate: no notification
        (False, False, 3,           "normal"),  # important
        (False, False, 4,           "major"),   # critical (<- Bodhi 'urgent'; reachable on Fedora)
        (True,  False, 1,           "normal"),
        (False, True,  2,           "major"),
    ]

    LABEL = {None: None, 0: "None", 1: "Low", 2: "Moderate", 3: "Important", 4: "Critical"}

    def test_table(self):
        for kernel, trivalent, sev, want in self.TABLE:
            changed, groups = [], []
            for nm in (("kernel",) if kernel else ()) + (("trivalent",) if trivalent else ()):
                changed.append({"name": nm, "src": nm, "dir": "upgrade"})
            if sev is not None:
                changed.append({"name": "glibc", "src": "glibc", "dir": "upgrade"})
                groups.append({"src": "glibc", "has_security_erratum": True,
                               "erratum_severity": self.LABEL[sev]})
            got = S.secureblue_notification({"changed": changed}, groups)
            self.assertEqual(got["level"], want,
                             f"kernel={kernel} trivalent={trivalent} sev={sev}")

    # Full chain for every Bodhi API word, through the same mapping Bodhi applies
    # before publishing (kernel/trivalent untouched, one security erratum):
    FULL_CHAIN = [
        ("urgent",      "major"),   # -> Critical(4)  -> critical urgency popup
        ("high",        "normal"),  # -> Important(3)
        ("medium",      "none"),    # -> Moderate(2)  -> no case arm
        ("low",         "none"),    # -> Low(1)       -> no case arm
        ("unspecified", "normal"),  # -> None(0)      -> 'unknown' arm
        ("",            "normal"),  # absent severity publishes as 'None' too
    ]

    def test_bodhi_word_full_chain(self):
        for bodhi_word, want in self.FULL_CHAIN:
            changed = [{"name": "nss", "src": "nss", "dir": "upgrade"}]
            groups = [{"src": "nss", "has_security_erratum": True,
                       "erratum_severity": S.bodhi_severity_as_updateinfo(bodhi_word)}]
            got = S.secureblue_notification({"changed": changed}, groups)
            self.assertEqual(got["level"], want, f"bodhi severity={bodhi_word!r}")

    def test_plain_bugfix_of_unimportant_package_is_silent(self):
        v = _verdict({"nano": pkg("nano", "8.0-1.fc44")}, {"nano": pkg("nano", "8.1-1.fc44")})
        self.assertEqual(v["secureblue_notification"]["level"], "none")
        self.assertEqual(v["level"], "skip")


class TestSecurityErratumFeedsTheRule(unittest.TestCase):
    def test_pushed_security_erratum_marks_the_group(self):
        old = pkg("nss", "4.39.0-4.fc44", "nss", [{"time": 1, "text": "- old"}])
        new = pkg("nss", "4.39.0-5.fc44", "nss", [{"time": 2, "text": "- fix"}])
        ups = {"nss": [{"alias": "FEDORA-2026-x", "type": "security", "severity": "medium",
                        "status": "stable", "nvrs": ["nss-4.39.0-5.fc44"], "notes": "",
                        "bugs": [], "title": "", "cves": []}]}
        d = S.pkg_diff({"nss": old}, {"nss": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", FakeBodhi(ups))
        g = S.group_by_src(d["changed"])[0]
        self.assertTrue(g["has_security_erratum"])
        # stored in the updateinfo spelling, which is what rpm-ostree is fed:
        # Bodhi 'medium' -> '<severity>Moderate</severity>' -> 2 -> no case arm
        # -> the desktop stays SILENT (answering 'unknown' -> NORMAL would
        # predict a popup that never appears)
        self.assertEqual(g["erratum_severity"], "Moderate")
        n = S.secureblue_notification(d, [g])
        self.assertEqual(n["max_advisory_severity"], "moderate")
        self.assertEqual(n["level"], "none")

    def test_urgent_security_erratum_is_major(self):
        """Bodhi 'urgent' publishes as <severity>Critical</severity> -> 4 ->
        'critical' arm -> MAJOR popup (and the verdict escalation applies).
        trivalent is NOT the only major trigger on Fedora."""
        old = pkg("nss", "4.39.0-4.fc44", "nss", [{"time": 1, "text": "- old"}])
        new = pkg("nss", "4.39.0-5.fc44", "nss", [{"time": 2, "text": "- fix CVE-2026-9999"}])
        ups = {"nss": [{"alias": "FEDORA-2026-z", "type": "security", "severity": "urgent",
                        "status": "stable", "nvrs": ["nss-4.39.0-5.fc44"], "notes": "",
                        "bugs": [], "title": "", "cves": []}]}
        d = S.pkg_diff({"nss": old}, {"nss": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", FakeBodhi(ups))
        g = S.group_by_src(d["changed"])[0]
        self.assertEqual(g["erratum_severity"], "Critical")
        n = S.secureblue_notification(d, [g])
        self.assertEqual(n["max_advisory_severity"], "critical")
        self.assertEqual(n["level"], "major")
        self.assertEqual(n["message"], "A major security vulnerability has been patched")

    def test_old_build_only_erratum_does_not_trigger(self):
        """An erratum that shipped the OLD build is a fix already installed."""
        old = pkg("nss", "4.39.0-4.fc44", "nss", [{"time": 1, "text": "- old"}])
        new = pkg("nss", "4.39.0-5.fc44", "nss", [{"time": 2, "text": "- fix"}])
        d = S.pkg_diff({"nss": old}, {"nss": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", FakeBodhi(NSS_UPDATES))
        g = S.group_by_src(d["changed"])[0]
        self.assertFalse(g["has_security_erratum"])
        self.assertEqual(S.secureblue_notification(d, [g])["level"], "none")

    def test_unpushed_erratum_does_not_trigger(self):
        old = pkg("nss", "4.39.0-4.fc44", "nss")
        new = pkg("nss", "4.39.0-5.fc44", "nss")
        ups = {"nss": [{"alias": "FEDORA-2026-y", "type": "security", "severity": "high",
                        "status": "testing", "nvrs": ["nss-4.39.0-5.fc44"], "notes": "",
                        "bugs": [], "title": "", "cves": []}]}
        d = S.pkg_diff({"nss": old}, {"nss": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", FakeBodhi(ups))
        g = S.group_by_src(d["changed"])[0]
        self.assertFalse(g["has_security_erratum"])
        self.assertEqual(S.secureblue_notification(d, [g])["level"], "none")


class TestManifestOnlyModeDoesNotOverclaim(unittest.TestCase):
    def test_prediction_is_unknown_without_versions(self):
        """--exact 0 never reads the rpmdb, so the package set is unknown and the
        popup cannot be predicted; answering 'none' there would be a claim."""
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": "?", "count_b": "?"}
        v = S.verdict_of(d, LD_FIX, META_IDENTICAL,
                         S.crosscheck_chunks(LD_FIX, d, versions_known=False), [], BSTATE)
        self.assertEqual(v["secureblue_notification"]["level"], "unknown")
        self.assertIsNone(v["secureblue_notification"]["message"])
        self.assertNotIn("secureblue will show", v["headline"])


# --------------------------------------------------------------------------- #
# G - the fast path must key off something that actually implies "no package
#     change".  rpmostree.inputhash does not: it is inherited from the Fedora
#     base (see TestVerdictNoChange), so two secureblue images can share it while
#     their package sets differ.
# --------------------------------------------------------------------------- #
class TestRpmdbChunkSelection(unittest.TestCase):
    def _img(self, layers):
        return {"layers": layers, "annotations": {}}

    def test_picks_the_smallest_matching_layer(self):
        """Must match the rule package_list() fetches by, or the fast path could
        verify one layer while the diff reads another."""
        img = self._img([
            {"digest": "sha256:big", "size": 900, "components": ["bigfiles/rpmdb.sqlite"]},
            {"digest": "sha256:small", "size": 40, "components": ["rpm/curl"]},
            {"digest": "sha256:zero", "size": 0, "components": ["bigfiles/rpmdb.sqlite"]},
        ])
        self.assertEqual(S.rpmdb_chunk(img)["digest"], "sha256:zero")

    def test_none_when_no_rpmdb_chunk(self):
        self.assertIsNone(S.rpmdb_chunk(self._img([
            {"digest": "sha256:a", "size": 10, "components": ["rpm/curl"]}])))

    def test_identical_digest_is_the_only_safe_skip_signal(self):
        """The measured 98613c9b784b/82baf9855818 pair: same inputhash, different
        content.  A digest comparison distinguishes them; inputhash does not."""
        same_ih = "4fde5b5a8c4ff655"
        a = self._img([{"digest": "sha256:db1", "size": 1, "components": ["bigfiles/rpmdb.sqlite"]}])
        b = self._img([{"digest": "sha256:db2", "size": 1, "components": ["bigfiles/rpmdb.sqlite"]}])
        a["annotations"]["rpmostree.inputhash"] = same_ih
        b["annotations"]["rpmostree.inputhash"] = same_ih
        self.assertEqual(a["annotations"]["rpmostree.inputhash"],
                         b["annotations"]["rpmostree.inputhash"])
        self.assertNotEqual(S.rpmdb_chunk(a)["digest"], S.rpmdb_chunk(b)["digest"])


class TestNoChangeRequiresVersionsToHaveBeenRead(unittest.TestCase):
    """Regression: in manifest-only mode `changed` is empty by construction, so the
    `no-change` guard passed while the rpmdb had never been fetched - the report
    then asserted "no package changed in the rpmdb" for a delta nobody inspected."""
    LD = {"download_bytes": 900 * 1024 * 1024, "total_size_b": 4 * 1024 ** 3,
          "chunks_changed": 40, "chunks_reused": 88, "chunks_a": 128, "chunks_b": 128,
          "changed_chunks": [], "changed_packages_from_chunks": ["kernel"]}
    META = {"kernel_a": "7.2.6-200.fc44.x86_64", "kernel_b": "7.2.6-200.fc44.x86_64",
            "inputhash_a": "4fde5b5a8c4f", "inputhash_b": "4fde5b5a8c4f",
            "commit_a": "4df81387", "commit_b": "4df81387"}

    def _v(self, count):
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": count, "count_b": count}
        return S.verdict_of(d, self.LD, self.META,
                            S.crosscheck_chunks(self.LD, d, versions_known=(count != "?")))

    def test_manifest_only_cannot_claim_no_change(self):
        v = self._v("?")
        self.assertNotEqual(v["level"], "no-change")
        self.assertFalse(v["package_versions_known"])
        self.assertNotIn("no package changed in the rpmdb", v["headline"])

    def test_exact_mode_with_empty_diff_still_claims_no_change(self):
        v = self._v(2242)
        self.assertEqual(v["level"], "no-change")
        self.assertTrue(v["package_versions_known"])
        self.assertIn("no package changed in the rpmdb", v["headline"])


class TestNoChangeWithSameRpmdb(unittest.TestCase):
    LD = {"download_bytes": 0, "total_size_b": 4 * 1024 ** 3,
          "chunks_changed": 0, "chunks_reused": 128, "chunks_a": 128, "chunks_b": 128,
          "changed_chunks": [], "changed_packages_from_chunks": []}
    META = {"kernel_a": "7.2.6-200.fc44.x86_64", "kernel_b": "7.2.6-200.fc44.x86_64",
            "inputhash_a": "4fde5b5a8c4f", "inputhash_b": "4fde5b5a8c4f",
            "commit_a": "4df81387", "commit_b": "4df81387"}

    def test_fast_path_same_rpmdb_claims_no_change(self):
        """When the rpmdb chunk digest is identical, the database is byte-for-byte
        the same, so versions are known to be unchanged even if rpmdb fetch was skipped."""
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": "?", "count_b": "?", "same_rpmdb": True}
        v = S.verdict_of(d, self.LD, self.META,
                         S.crosscheck_chunks(self.LD, d, versions_known=True))
        self.assertEqual(v["level"], "no-change")
        self.assertTrue(v["package_versions_known"])
        self.assertIn("no package changed in the rpmdb", v["headline"])
        self.assertIn("rpmdb chunk 摘要完全一致", v["headline_zh"])


class TestEscalationFromConsider(unittest.TestCase):
    def test_trivalent_escalation_removes_skip_advice(self):
        """If an update had an important package bump (initially 'consider' with
        'Reasonable to skip if the download matters to you'), escalating to 'update-now'
        via trivalent must strip that contradictory advice."""
        pa = {"trivalent": pkg("trivalent", "153.0-1"), "curl": pkg("curl", "8.0-1")}
        pb = {"trivalent": pkg("trivalent", "154.0-1"), "curl": pkg("curl", "8.0-2")}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        v = S.verdict_of(d, LD_FIX, META_IDENTICAL, {})
        self.assertEqual(v["level"], "update-now")
        self.assertEqual(v["escalated_by_secureblue_rule"], "consider")
        self.assertNotIn("Reasonable to skip", v["headline"])
        self.assertNotIn("可以合理地跳过", v["headline_zh"])
        self.assertIn("secureblue escalates this to major", v["headline"])
        self.assertIn("secureblue 将此更新上调为重大更新", v["headline_zh"])
        self.assertIn("trivalent 已升级", v["headline_zh"])


class TestSecureblueNotificationLocalization(unittest.TestCase):
    def test_why_zh_present_and_localized(self):
        d = {"changed": [{"name": "trivalent", "src": "trivalent", "dir": "upgrade"},
                         {"name": "kernel", "src": "kernel", "dir": "upgrade"}]}
        n = S.secureblue_notification(d)
        self.assertTrue(len(n["why_zh"]) >= 2)
        self.assertIn("trivalent 已升级", n["why_zh"][0])
        self.assertIn("内核已升级", n["why_zh"][1])


class TestRenderMarkdownReportSeparation(unittest.TestCase):
    def test_pure_chinese_first_then_dashes_then_pure_english(self):
        """Report output must have pure Chinese first, followed by '---' separator,
        then pure English."""
        pa = {"trivalent": pkg("trivalent", "153.0-1"), "nano": pkg("nano", "8.0-1")}
        pb = {"trivalent": pkg("trivalent", "154.0-1"), "nano": pkg("nano", "8.1-1")}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        ld = {"download_bytes": 1024, "total_size_b": 10240, "chunks_changed": 1,
              "chunks_reused": 10, "chunks_a": 11, "chunks_b": 11,
              "changed_chunks": [{"size": 1024, "components": ["rpm/nano"]}],
              "changed_packages_from_chunks": ["nano"], "download_pct": 10.0}
        meta = {"kernel_a": "k", "kernel_b": "k", "inputhash_a": "h", "inputhash_b": "h"}
        v = S.verdict_of(d, ld, meta, {})
        img_a = {"ref": "a", "digest": "sha256:1111111111111111111", "annotations": {"rpmostree.inputhash": "h"}}
        img_b = {"ref": "b", "digest": "sha256:2222222222222222222", "annotations": {"rpmostree.inputhash": "h"}}

        md = S.render_markdown("Test Subject", img_a, img_b, d, ld, v, ["Note / 备注"])
        self.assertIn("\n\n---\n\n", md)
        parts = md.split("\n\n---\n\n")
        self.assertEqual(len(parts), 2)
        zh_part, en_part = parts[0], parts[1]

        # Chinese part checks
        self.assertIn("## 结论: ", zh_part)
        self.assertIn("## secureblue 桌面通知预测", zh_part)
        self.assertIn("如果现在更新，需要下载", zh_part)
        self.assertIn("对比引用", zh_part)
        self.assertIn("由 `sbwatch` 生成", zh_part)
        self.assertNotIn("## Verdict: ", zh_part)
        self.assertNotIn("## secureblue Notification Prediction", zh_part)
        self.assertNotIn("If you update, you download", zh_part)
        self.assertNotIn("Generated by `sbwatch`", zh_part)

        # English part checks
        self.assertIn("## Verdict: ", en_part)
        self.assertIn("## secureblue Notification Prediction", en_part)
        self.assertIn("If you update, you download", en_part)
        self.assertIn("compared refs", en_part)
        self.assertIn("Generated by `sbwatch`", en_part)
        self.assertNotIn("## 结论: ", en_part)
        self.assertNotIn("## secureblue 桌面通知预测", en_part)
        self.assertNotIn("如果现在更新，需要下载", en_part)
        self.assertNotIn("由 `sbwatch` 生成", en_part)


class TestDoDiffFastPathSameRpmdb(unittest.TestCase):
    def test_do_diff_with_same_rpmdb_sets_no_change(self):
        """When args.exact == 0 (e.g. from cmd_check --fast) and rpmdb chunk digest
        is identical, do_diff must set diff['same_rpmdb'] = True, versions_known = True,
        and verdict level must be 'no-change', without asserting 'chunk-level mode'."""
        import types
        args = types.SimpleNamespace(
            image="secureblue/silverblue-main-hardened",
            arch="amd64",
            exact=0,
            fast=True,
            force=False,
            keep_order=True,
            no_bodhi=True,
            cache_dir=None,
            cosign_pub=None,
            require_cosign=False,
        )
        img_a = {
            "ref": "a",
            "digest": "sha256:1111111111111111111",
            "created": "2026-09-20T00:00:00Z",
            "annotations": {"rpmostree.inputhash": "ih1", "ostree.linux": "7.2.6"},
            "layers": [
                {"digest": "sha256:rpmdb_same_digest", "size": 100, "components": ["bigfiles/rpmdb.sqlite"], "stability": ""},
                {"digest": "sha256:layer1", "size": 500, "components": ["rpm/app"], "stability": ""},
            ]
        }
        img_b = {
            "ref": "b",
            "digest": "sha256:2222222222222222222",
            "created": "2026-09-21T00:00:00Z",
            "annotations": {"rpmostree.inputhash": "ih2", "ostree.linux": "7.2.6"},
            "layers": [
                {"digest": "sha256:rpmdb_same_digest", "size": 100, "components": ["bigfiles/rpmdb.sqlite"], "stability": ""},
                {"digest": "sha256:layer2", "size": 500, "components": ["rpm/app"], "stability": ""},
            ]
        }

        res = S.do_diff(args, "a", "b", images=(img_a, img_b))
        self.assertTrue(res["diff"]["same_rpmdb"])
        self.assertTrue(res["xc"]["versions_known"])
        self.assertEqual(res["verdict"]["level"], "no-change")
        self.assertTrue(res["verdict"]["package_versions_known"])
        self.assertIn("identical rpmdb chunk digest", res["verdict"]["headline"])
        self.assertIn("rpmdb chunk 摘要完全一致", res["verdict"]["headline_zh"])
        self.assertNotIn("chunk-level mode", res["verdict"]["headline"])
        self.assertNotIn("未读取任何软件包版本", res["verdict"]["headline_zh"])


class TestRenderMarkdownNotesWithSlash(unittest.TestCase):
    def test_note_with_slashes_in_english_not_broken(self):
        """Notes containing ' / ' within the English prose must not be split prematurely."""
        img_a = {"ref": "a", "digest": "sha256:1111111111111111111", "annotations": {}}
        img_b = {"ref": "b", "digest": "sha256:2222222222222222222", "annotations": {}}
        diff = {"added": [], "removed": [], "downgrades": [], "changed": [], "count_a": 10, "count_b": 10}
        ldiff = {"download_bytes": 0, "total_size_b": 1000, "chunks_changed": 0,
                 "chunks_reused": 1, "chunks_b": 1, "changed_chunks": [], "download_pct": 0.0}
        verdict = {"level": "no-change", "headline": "ok", "headline_zh": "正常",
                   "security_pkgs": []}

        # Test both BiText and raw string with 'new / dropped'
        bi_note = S.T("changelog scan capped at 40 new / 30 dropped entries per package; 1 pkg",
                      "更新日志扫描上限为每包 40 条新增 / 30 条丢失条目；1 个包")
        str_note = ("changelog scan capped at 40 new / 30 dropped entries; more "
                    "/ 更新日志扫描上限为每包 40 条新增 / 30 条丢失条目；更多")

        md = S.render_markdown("Test Subject", img_a, img_b, diff, ldiff, verdict, [bi_note, str_note])
        zh_part, en_part = md.split("\n\n---\n\n")

        # English part must contain full sentence, not truncated at '40 new'
        self.assertIn("40 new / 30 dropped entries per package; 1 pkg", en_part)
        self.assertIn("40 new / 30 dropped entries; more", en_part)
        self.assertNotIn("更新日志扫描上限", en_part)

        # Chinese part must contain Chinese translation and no English residual
        self.assertIn("更新日志扫描上限为每包 40 条新增 / 30 条丢失条目；1 个包", zh_part)
        self.assertIn("更新日志扫描上限为每包 40 条新增 / 30 条丢失条目；更多", zh_part)
        self.assertNotIn("dropped entries", zh_part)


class TestRebuildNotCountedAsUpgraded(unittest.TestCase):
    def test_rebuild_excluded_from_upgraded(self):
        d = {"changed": [{"name": "kernel", "src": "kernel", "dir": "rebuild"}]}
        n = S.secureblue_notification(d)
        self.assertFalse(n["kernel_updated"])



# --------------------------------------------------------------------------- #
# I - secureblue's kernel is a rebuild of Fedora's, and rpm-ostree never attaches
#     Fedora's advisory to it. Everything below locks down that distinction.
# --------------------------------------------------------------------------- #
SEC_UPD = {"alias": "FEDORA-2026-abcd", "type": "security", "severity": "urgent",
           "status": "stable", "title": "kernel: important fix",
           "notes": "Fixes CVE-2026-1111", "date_approved": "2026-09-20",
           "date_stable": "2026-09-21", "bugs": [],
           "nvrs": ["kernel-7.2.8-200.fc44"]}


def _upd_for(nvr, sev="urgent", status="stable", alias="FEDORA-2026-abcd"):
    return dict(SEC_UPD, alias=alias, severity=sev, status=status, nvrs=[nvr])


class TestAdvisoryAttachment(unittest.TestCase):
    """has_security_erratum must mean exactly what rpm-ostree's HY_EQ means."""

    def test_secureblue_release_erratum_is_corresponding_not_attached(self):
        # secureblue's kernel really is a rebuild of Fedora's build, and Fedora
        # publishes an erratum for that build - but pool_evrcmp() compares the
        # release strings too, so rpm-ostree attaches nothing to this package.
        new = pkg("kernel", "7.2.8-200.secureblue.1.fc44")
        info = S.classify_change(None, new, "F44", FakeBodhi({"kernel": [SEC_UPD]}))
        self.assertTrue(info["security"])              # the fix content is real
        self.assertTrue(info["advisory_corresponding"])
        self.assertFalse(info["has_security_erratum"])  # but not an advisory of this build
        self.assertEqual(info["erratum"]["matched_nvr"], "kernel-7.2.8-200.fc44")

    def test_exact_release_is_attached(self):
        new = pkg("kernel", "7.2.8-200.fc44")
        info = S.classify_change(None, new, "F44", FakeBodhi({"kernel": [SEC_UPD]}))
        self.assertTrue(info["has_security_erratum"])
        self.assertFalse(info["advisory_corresponding"])
        self.assertEqual(info["erratum_severity"], "Critical")

    def test_corresponding_erratum_cannot_forge_a_major_notification(self):
        new = pkg("kernel", "7.2.8-200.secureblue.1.fc44")
        old = pkg("kernel", "7.2.7-200.secureblue.1.fc44")
        c = {"name": "kernel", "old": old, "new": new, "src": "kernel", "dir": "upgrade",
             "cls": S.classify_change(old, new, "F44", FakeBodhi({"kernel": [SEC_UPD]}))}
        groups = S.group_by_src([c])
        sbn = S.secureblue_notification({"changed": [c]}, groups)
        # kernel really moved, so a NORMAL notification is expected - but the
        # Critical severity (which rpm-ostree would never see) must not turn it
        # into a MAJOR one.
        self.assertEqual(sbn["level"], "normal")
        self.assertEqual(sbn["max_advisory_severity"], "none")
        self.assertEqual(sbn["security_advisory_count"], 0)

    def test_exact_erratum_still_forges_the_major_notification(self):
        new, old = pkg("curl", "8.1-1.fc44"), pkg("curl", "8.0-1.fc44")
        ups = [_upd_for("curl-8.1-1.fc44")]
        c = {"name": "curl", "old": old, "new": new, "src": "curl", "dir": "upgrade",
             "cls": S.classify_change(old, new, "F44", FakeBodhi({"curl": ups}))}
        sbn = S.secureblue_notification({"changed": [c]}, S.group_by_src([c]))
        self.assertEqual(sbn["level"], "major")
        self.assertEqual(sbn["max_advisory_severity"], "critical")

    def test_added_package_advisory_also_drives_the_prediction(self):
        # rpmostree_advisories_variant() sees every package that is *new* in the
        # deployment, including added ones - predicting "none" here was wrong.
        new = pkg("cups", "2.4.16-1.fc44")
        added_cls = {"cups": S.classify_change(None, new, "F44",
                                               FakeBodhi({"cups": [_upd_for("cups-2.4.16-1.fc44")]}))}
        diff = {"added": ["cups"], "removed": [], "changed": []}
        sbn = S.secureblue_notification(diff, [], added_cls)
        self.assertEqual(sbn["level"], "major")
        self.assertEqual(sbn["added_packages_with_advisories"], ["cups"])


# --------------------------------------------------------------------------- #
# J - verdict plumbing: a mode that read nothing must not recommend anything
# --------------------------------------------------------------------------- #
LD_SMALL = {"download_bytes": 900 * 1024 * 1024, "total_size_b": 4 * 1024 ** 3,
            "chunks_a": 130, "chunks_b": 132, "chunks_changed": 40, "chunks_reused": 92,
            "changed_chunks": [], "changed_packages_from_chunks": [f"p{i}" for i in range(241)]}
DIFF_MANIFEST_ONLY = {"added": [], "removed": [], "downgrades": [], "changed": [],
                      "count_a": "?", "count_b": "?", "same_rpmdb": False}


class TestManifestOnlyVerdict(unittest.TestCase):
    def test_level_is_unknown_not_skip(self):
        xc = S.crosscheck_chunks(LD_SMALL, DIFF_MANIFEST_ONLY, versions_known=False)
        v = S.verdict_of(DIFF_MANIFEST_ONLY, LD_SMALL, {"kernel_a": "7.2.6", "kernel_b": "7.2.6"}, xc)
        # verdict_of itself still says "skip": it was handed an empty package diff and
        # has no way to know why. do_diff knows, and downgrades it.
        self.assertEqual(v["level"], "skip")
        v = S.degrade_manifest_only_verdict(v, LD_SMALL)
        self.assertEqual(v["level"], "unknown")
        self.assertIn("241", v["headline"])
        self.assertIn("NOT read", v["headline"])
        self.assertIn("未读取", v["headline_zh"])
        self.assertIn("--exact 0", v["level_basis"])

    def test_level_basis_is_machine_readable_for_every_regular_level(self):
        base = {"added": [], "removed": [], "downgrades": [], "changed": []}
        meta = {"kernel_a": "1", "kernel_b": "1"}
        v = S.verdict_of(dict(base, count_a=1, count_b=1), LD_FIX, meta,
                         S.crosscheck_chunks(LD_FIX, base, {}))
        self.assertEqual(v["level"], "no-change")
        self.assertIn("no package", v["level_basis"])

    def test_no_change_still_carries_the_backlog_note(self):
        # The no-change branch used to `return` before everything below it ran, so
        # the backlog note (and every other late annotation) vanished.
        base = {"added": [], "removed": [], "downgrades": [], "changed": []}
        backlog = [{"name": "openssl", "severity": "important", "want": "3.1-2",
                    "have": "3.1-1", "src": "openssl", "alias": "FEDORA-2026-x", "cves": []}]
        v = S.verdict_of(dict(base, count_a=1, count_b=1), LD_FIX,
                         {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(LD_FIX, base, {}), backlog)
        self.assertEqual(v["level"], "no-change")          # backlog must not raise it
        self.assertIn("still misses 1 published stable", v["headline"])

    def test_silent_rebuild_scan_is_not_capped_at_60(self):
        silent = [(f"pkg{i:03d}", 1000) for i in range(70)] + [("kernel", 5)]
        xc = {"silent_rebuilds": silent, "non_package_bytes": 0, "versions_known": True}
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"}, xc)
        self.assertIn("kernel", v["silent_important"])


# --------------------------------------------------------------------------- #
# K - smaller failures that used to be silent or fatal
# --------------------------------------------------------------------------- #
class _BoomRegistry:
    """Registry whose only manifest probe raises what _open() would raise."""

    def __init__(self, code):
        self.code = code

    def _open(self, path, accept):
        raise S.RegistryError("boom", http_code=self.code)


class TestFixesThatUsedToBeSilent(unittest.TestCase):
    def test_tag_exists_is_quiet_for_404_only(self):
        self.assertIsNone(S.tag_exists(_BoomRegistry(404), "20260913"))
        warn = []
        self.assertIsNone(S.tag_exists(_BoomRegistry(503), "20260914", warn=warn))
        self.assertEqual(len(warn), 1)
        self.assertIn("503", warn[0])
        self.assertIn("20260914", warn[0])
        warn = []
        self.assertIsNone(S.tag_exists(_BoomRegistry(None), "20260915", warn=warn))
        self.assertIn("network error", warn[0])

    def test_backlog_severity_order_places_medium_above_low(self):
        class B:
            failed = 0
            skipped = 0

            def updates_for_src(self, src, rel):
                sev = {"kernel": "low", "glibc": "medium"}[src]
                return [dict(SEC_UPD, severity=sev, nvrs=[f"{src}-2.0-1.fc44"])]

        pkgs = {"kernel": pkg("kernel", "1.0-1.fc44"), "glibc": pkg("glibc", "1.0-1.fc44")}
        rows, _ = S.security_backlog(pkgs, "F44", B(), limit=5)
        # "medium" is Bodhi's own word; the table used to know only "moderate", so
        # a medium erratum sorted below low (rank 0 < 1).
        self.assertEqual([r["name"] for r in rows], ["glibc", "kernel"])

    def test_null_bodhi_build_nvr_is_skipped(self):
        class B:
            failed = 0
            skipped = 0

            def updates_for_src(self, src, rel):
                return [dict(SEC_UPD, nvrs=[None, "kernel-2.0-1.fc44"])]

        rows, _ = S.security_backlog({"kernel": pkg("kernel", "1.0-1.fc44")}, "F44", B(), limit=3)
        self.assertEqual([r["want"] for r in rows], ["2.0-1.fc44"])

    def test_coverage_line_tolerates_the_dict_do_diff_actually_builds(self):
        # do_diff initialises coverage without skipped_names; coverage_line used to
        # KeyError on it the moment anything was truncated.
        cov = {"candidates": 9, "checked": 3, "skipped": 6, "failed": 0,
               "pool_missing": [], "pool_size": 0}
        self.assertIn("6", str(S.coverage_line(cov)))

    def test_group_by_src_accepts_entries_without_dir(self):
        g = S.group_by_src([{"name": "foo", "src": "foo", "cls": {},
                             "old": {"evr": "1-1"}, "new": {"evr": "2-1"}}])
        self.assertEqual(g[0]["src"], "foo")
        self.assertFalse(g[0]["downgrade"])

    def test_missing_kernel_annotation_is_not_rendered_as_None(self):
        d = {"added": [], "removed": [], "downgrades": [],
             "changed": [{"name": "curl", "src": "curl", "dir": "upgrade",
                          "old": {"evr": "8.0-1"}, "new": {"evr": "8.1-1"}}],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "7.2.6-200.fc44.x86_64", "kernel_b": None},
                         S.crosscheck_chunks(LD_FIX, d, {"curl": "curl"}))
        self.assertNotIn("None", v["headline"])
        self.assertIn("→ ?", v["headline"])

    def test_multilib_collision_is_recorded_not_dropped(self):
        pkgs = S.PackageTable()
        S.table_put(pkgs, {"name": "foo", "arch": "i686", "evr": "1-1", "version": "1",
                           "release": "1", "epoch": ""})
        S.table_put(pkgs, {"name": "foo", "arch": "x86_64", "evr": "2-1", "version": "2",
                           "release": "1", "epoch": ""})
        self.assertEqual(pkgs["foo"]["arch"], "x86_64")
        self.assertEqual(len(pkgs.collisions), 1)
        self.assertEqual(pkgs.collisions[0]["shadowed_arch"], "i686")

    def test_read_header_reports_what_it_could_not_parse(self):
        import struct as _struct
        stats = {}
        # size fields that cannot add up
        self.assertEqual(S.read_header(_struct.pack(">II", 4, 4096), stats), {})
        self.assertEqual(stats["headers_rejected"], 1)
        # a string field with no NUL terminator
        hdr = _struct.pack(">II", 1, 3) + _struct.pack(">IIII", 1000, 6, 0, 1) + b"abc"
        stats = {}
        self.assertEqual(S.read_header(hdr, stats), {})
        self.assertEqual(stats.get("fields_skipped"), 1)

    def test_atomic_write_text_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.md")
            S._atomic_write_text(path, "hello\n")
            self.assertEqual(open(path).read(), "hello\n")
            self.assertEqual([f for f in os.listdir(d) if "tmp" in f], [])

    def test_bodhi_unavailable_is_not_blamed_on_no_bodhi(self):
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(LD_FIX, d, {}), None, {"unavailable": 1})
        self.assertIn("no Fedora release", v["headline"])
        self.assertNotIn("--no-bodhi", v["headline"])

    def test_downgrade_alone_raises_the_level(self):
        d = {"added": [], "removed": [], "downgrades": [{"name": "foo"}],
             "changed": [{"name": "foo", "src": "foo", "dir": "downgrade",
                          "old": {"evr": "2-1"}, "new": {"evr": "1-1"}}],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(LD_FIX, d, {"foo": "foo"}))
        self.assertEqual(v["level"], "consider")

    def test_changelog_cves_dropped_no_longer_escalates(self):
        d = {"added": [], "removed": [], "downgrades": [],
             "changed": [{"name": "foo", "src": "foo", "dir": "upgrade",
                          "old": {"evr": "1-1"}, "new": {"evr": "2-1"},
                          "cls": {"cves": [], "cves_dropped": ["CVE-2019-0001"],
                                  "security": False, "important_src": False,
                                  "has_security_erratum": False, "aliases": [],
                                  "already_had": [], "not_pushed": [], "why": [],
                                  "erratum": None, "erratum_severity": "", "sev_rank": 0}}],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(LD_FIX, d, {"foo": "foo"}))
        self.assertEqual(v["level"], "skip")
        self.assertIn("changelog", v["headline"])
        self.assertIn("CVE-2019-0001", v["headline"])

    def test_changelog_diff_sees_entries_added_in_the_same_second(self):
        old = {"name": "foo", "src": "foo", "version": "1", "release": "1", "epoch": "",
               "changelog": [{"time": 1000, "who": "a", "text": "- fix CVE-2020-0001"}]}
        new = dict(old, version="2", changelog=[
            {"time": 1000, "who": "a", "text": "- fix CVE-2020-0001"},
            {"time": 1000, "who": "a", "text": "- Fix CVE-2026-9999"}])
        info = S.classify_change(old, new, "F44", None)
        # keyed by timestamp alone, the second entry was "already there"
        self.assertEqual(info["changelog_scan"]["new_total"], 1)
        self.assertEqual(info["cves"], ["CVE-2026-9999"])

    def test_duplicate_identical_entries_are_not_counted_as_new(self):
        old = {"name": "foo", "src": "foo", "version": "1", "release": "1", "epoch": "",
               "changelog": [{"time": 5, "who": "a", "text": "- x"}]}
        new = dict(old, version="2", changelog=[{"time": 5, "who": "a", "text": "- x"}])
        info = S.classify_change(old, new, "F44", None)
        self.assertEqual(info["changelog_scan"]["new_total"], 0)


# --------------------------------------------------------------------------- #
# L - the workflow's own supply chain
# --------------------------------------------------------------------------- #
class TestWorkflowHygiene(unittest.TestCase):
    REPO = os.path.dirname(HERE)

    def _workflow(self):
        return open(os.path.join(self.REPO, ".github", "workflows", "sbwatch.yml")).read()

    def test_every_action_is_pinned_to_a_commit_sha(self):
        wf = self._workflow()
        uses = re.findall(r"uses:\s*(\S+)", wf)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$",
                             f"{u} is not pinned to a 40-hex commit")

    def test_cosign_pub_is_vendored_and_its_hash_is_enforced(self):
        wf = self._workflow()
        with open(os.path.join(self.REPO, "cosign.pub"), "rb") as fh:
            digest = __import__("hashlib").sha256(fh.read()).hexdigest()
        self.assertIn(digest, wf)
        # the key must not be fetched at run time any more
        self.assertNotIn("curl -fsSL -o cosign.pub", wf)

    def test_write_permissions_are_scoped_to_the_watch_job(self):
        wf = self._workflow()
        self.assertIn("permissions:\n  contents: read\n", wf)
        head = wf.split("jobs:")[0]
        self.assertNotIn("actions: write", head)
        self.assertNotIn("issues: write", head)

    def test_an_inconclusive_run_is_not_green(self):
        wf = self._workflow()
        self.assertIn("steps.check.outputs.verdict == 'unknown'", wf)
        self.assertIn("exit 1", wf)
