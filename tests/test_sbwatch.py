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
  D      dead code must stay dead (incl. Bodhi._read_cache, Registry.__enter__)
  E3     state writes are atomic
  E6     pkg_diff: epoch-only changes must be visible
  E7     pick_tar_member: largest match wins, tar order must not matter
"""
import io
import json
import os
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
