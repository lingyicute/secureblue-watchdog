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
  M      no silent truncation: every capped list/string states - and counts - what
         it dropped; a security table elides CVE ids only into a complete listing
         below it; payload lists (cves/aliases/dropped) are never sliced at all
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


# The live FEDORA-2026-40db9b80a2 bug list (webkitgtk-2.54.0-2.fc44 -> 113 ids).
# `sorted()` puts the oldest first, so the security table's [:6] used to show the
# six 2023/2024 leftovers and hide every 2026 id - the report read as "WebKit is
# patching 2023 CVEs" while 107 current ones were invisible.
WEBKITGTK_113 = [
    "CVE-2023-4860", "CVE-2024-7966", "CVE-2024-8193", "CVE-2024-8198",
    "CVE-2024-8636", "CVE-2024-9123", "CVE-2025-0436", "CVE-2025-0444",
    "CVE-2026-3538", "CVE-2026-3909", "CVE-2026-3931", "CVE-2026-4460",
    "CVE-2026-5870", "CVE-2026-6298", "CVE-2026-6364", "CVE-2026-7353",
    "CVE-2026-7920", "CVE-2026-7923", "CVE-2026-7949", "CVE-2026-8510",
    "CVE-2026-8579", "CVE-2026-9892", "CVE-2026-9893", "CVE-2026-9909",
    "CVE-2026-9923", "CVE-2026-9981", "CVE-2026-9983", "CVE-2026-9998",
    "CVE-2026-10009", "CVE-2026-10011", "CVE-2026-10012", "CVE-2026-10020",
    "CVE-2026-10925", "CVE-2026-10941", "CVE-2026-10977", "CVE-2026-10985",
    "CVE-2026-10993", "CVE-2026-11024", "CVE-2026-11039", "CVE-2026-11057",
    "CVE-2026-11099", "CVE-2026-11121", "CVE-2026-11124", "CVE-2026-11159",
    "CVE-2026-11663", "CVE-2026-11675", "CVE-2026-13781", "CVE-2026-13820",
    "CVE-2026-13841", "CVE-2026-13885", "CVE-2026-13971", "CVE-2026-14387",
    "CVE-2026-14389", "CVE-2026-14410", "CVE-2026-14414", "CVE-2026-14419",
    "CVE-2026-14427", "CVE-2026-14429", "CVE-2026-15766", "CVE-2026-15774",
    "CVE-2026-16417", "CVE-2026-17653", "CVE-2026-17702", "CVE-2026-17712",
    "CVE-2026-17745", "CVE-2026-17757", "CVE-2026-17771", "CVE-2026-17914",
    "CVE-2026-17992", "CVE-2026-19154", "CVE-2026-19160", "CVE-2026-19161",
    "CVE-2026-19173", "CVE-2026-19176", "CVE-2026-43804", "CVE-2026-64713",
    "CVE-2026-64715", "CVE-2026-64728", "CVE-2026-64730", "CVE-2026-64753",
    "CVE-2026-64757", "CVE-2026-64778", "CVE-2026-64779", "CVE-2026-64780",
    "CVE-2026-64782", "CVE-2026-64783", "CVE-2026-64784", "CVE-2026-65331",
    "CVE-2026-65332", "CVE-2026-65333", "CVE-2026-65334", "CVE-2026-65335",
    "CVE-2026-65336", "CVE-2026-65337", "CVE-2026-65338", "CVE-2026-65340",
    "CVE-2026-65341", "CVE-2026-65351", "CVE-2026-76041", "CVE-2026-78376",
    "CVE-2026-78914", "CVE-2026-78958", "CVE-2026-79020", "CVE-2026-79112",
    "CVE-2026-79144", "CVE-2026-79147", "CVE-2026-83596", "CVE-2026-84359",
    "CVE-2026-84635", "CVE-2026-85049", "CVE-2026-91733", "CVE-2026-91740",
    "CVE-2026-91747",
]


def webkitgtk_report():
    """Render a report for the live webkitgtk case: 2.52.5 -> 2.54.0, one erratum
    carrying all 113 ids. Returns (markdown, zh_part, en_part, diff)."""
    old = pkg("webkitgtk", "2.52.5-1.fc44", "webkitgtk",
              [{"time": 1, "text": "- 2.52.5"}])
    new = pkg("webkitgtk", "2.54.0-2.fc44", "webkitgtk",
              [{"time": 2, "text": "- Update to 2.54.0"}])
    ups = {"webkitgtk": [{"alias": "FEDORA-2026-40db9b80a2", "type": "security",
                          "severity": "high", "status": "stable",
                          "nvrs": ["webkitgtk-2.54.0-2.fc44"],
                          "notes": "WebKit Security fixes. " + " ".join(WEBKITGTK_113),
                          "bugs": [], "title": "", "cves": []}]}
    d = S.pkg_diff({"webkitgtk": old}, {"webkitgtk": new})
    for c in d["changed"]:
        c["cls"] = S.classify_change(c["old"], c["new"], "F44", FakeBodhi(ups))
    ld = {"download_bytes": 796 * 1024 * 1024, "total_size_b": 4 * 1024 ** 3,
          "chunks_changed": 15, "chunks_reused": 113, "chunks_a": 128, "chunks_b": 128,
          "changed_chunks": [{"size": 1024, "components": ["rpm/webkitgtk"]}],
          "changed_packages_from_chunks": ["webkitgtk"], "download_pct": 21.0}
    meta = {"kernel_a": "k", "kernel_b": "k", "inputhash_a": "h", "inputhash_b": "h"}
    v = S.verdict_of(d, ld, meta, {})
    ia = {"ref": "a", "digest": "sha256:" + "1" * 64,
          "annotations": {"rpmostree.inputhash": "h"}}
    ib = {"ref": "b", "digest": "sha256:" + "2" * 64,
          "annotations": {"rpmostree.inputhash": "h"}}
    md = S.render_markdown("s", ia, ib, d, ld, v, [])
    zh, en = md.split("\n\n---\n\n")
    return md, zh, en, d


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

    def test_added_or_removed_package_is_not_a_same_version_rebuild(self):
        # a chunk that moved because the package set changed was not "rebuilt":
        # `newpkg` is new, `libbar` gained a subpackage and `foo` lost one
        ld = {"changed_chunks": [{"components": ["rpm/libbar"], "size": 16},
                                 {"components": ["rpm/newpkg"], "size": 9},
                                 {"components": ["rpm/foo"], "size": 7},
                                 {"components": ["rpm/systemd"], "size": 5}]}
        diff = {"changed": [], "added": ["libbar-data", "newpkg"], "removed": ["foo-doc"]}
        src_of = {"libbar-data": "libbar", "libbar": "libbar", "newpkg": "newpkg",
                  "foo-doc": "foo", "foo": "foo", "systemd": "systemd"}
        xc = S.crosscheck_chunks(ld, diff, src_of)
        self.assertEqual([n for n, _ in xc["silent_rebuilds"]], ["systemd"])


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

    def test_created_is_cut_to_whole_seconds_with_its_zone(self):
        # a light resolve only sees the annotation, which carries nanoseconds; a
        # [:20] slice left "...:53." - no zone, and not the config's spelling
        self.assertEqual(S.rfc3339_seconds("2026-11-10T06:15:53.905949731+00:00"),
                         "2026-11-10T06:15:53Z")
        self.assertEqual(S.rfc3339_seconds("2026-11-10T06:15:53Z"), "2026-11-10T06:15:53Z")
        self.assertEqual(S.rfc3339_seconds("2026-11-10T08:15:53.5+02:00"),
                         "2026-11-10T08:15:53+02:00")
        self.assertEqual(S.rfc3339_seconds(None), "")


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
                json.dump({"cache_version": S.BODHI_CACHE_VERSION, "total": 1,
                           "truncated": False,
                           "updates": [{"alias": "FEDORA-2026-1"}]}, fh)
            self.assertEqual(b.updates_for_src("rpm", "F44"),
                             [{"alias": "FEDORA-2026-1"}])
            self.assertEqual(b.truncated_src, set())

    def test_cache_without_the_version_marker_is_refetched_not_trusted(self):
        """v1 caches stored bug titles clipped to 200 chars *before* the CVE ids
        were extracted from them, so they can be missing CVEs outright. A cache
        that cannot prove it is v2 must be ignored, not read."""
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=0)      # 0 calls => provably offline
            cf = b._cf("webkitgtk-F44")
            payload = [{"alias": "FEDORA-2026-40db9b80a2", "type": "security",
                        "status": "stable", "severity": "high", "nvrs": [],
                        "notes": "", "bugs": [], "title": "",
                        "cves": ["CVE-2023-4860"]}]
            with open(cf, "w") as fh:
                json.dump({"total": 1, "truncated": False, "updates": payload}, fh)
            self.assertIsNone(b._read_cache_entry(cf))
            self.assertEqual(b.updates_for_src("webkitgtk", "F44"), [])   # not the cache
            self.assertEqual(b.skipped, 1)             # it went for a refetch instead

    def test_truncated_cache_marks_the_source(self):
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=3)
            cf = b._cf("kernel-F44")
            with open(cf, "w") as fh:
                json.dump({"cache_version": S.BODHI_CACHE_VERSION, "total": 999,
                           "truncated": True, "updates": []}, fh)
            b.updates_for_src("kernel", "F44")
            self.assertEqual(b.truncated_src, {"kernel"})

    def test_repeat_lookup_is_served_from_memory_not_reread_from_disk(self):
        """classify_change() asks once per binary package, so every kernel
        subpackage asks for `kernel`: the answer already in memory must be
        reused instead of re-reading and re-parsing the cache file each time."""
        with tempfile.TemporaryDirectory() as d:
            b = S.Bodhi(cache_dir=d, max_calls=0)      # 0 calls => provably offline
            cf = b._cf("kernel-F44")
            payload = [{"alias": "FEDORA-2026-1"}]
            with open(cf, "w") as fh:
                json.dump({"cache_version": S.BODHI_CACHE_VERSION, "total": 1,
                           "truncated": False, "updates": payload}, fh)
            self.assertEqual(b.updates_for_src("kernel", "F44"), payload)
            with open(cf, "w") as fh:                  # a re-read would trip on this
                fh.write("{ not json")
            self.assertEqual(b.updates_for_src("kernel", "F44"), payload)
            self.assertTrue(os.path.exists(cf), "the cache file was re-read")


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

    def _run(self, total, max_pages=None, max_calls=99, cache_dir=None):
        b = S.Bodhi(cache_dir=cache_dir, max_calls=max_calls, sleep=0)
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

    def test_max_bodhi_caps_every_page_and_is_not_cached_as_complete(self):
        import contextlib
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as td, \
                contextlib.redirect_stderr(io.StringIO()):
            ups, b, fake = self._run(250, max_calls=2, cache_dir=td)
            self.assertEqual(fake.calls, 2)            # the budget, not 3 pages
            self.assertEqual(len(ups), 200)
            self.assertEqual(b.truncated_src, {"kernel"})
            self.assertEqual(os.listdir(td), [])       # a partial answer is not persisted


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
        self.assertIn("--backlog-candidates", cov_line)   # the cap that cut them
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

    def _render(self, diff, notes=()):
        img_a = {"ref": "a", "digest": "sha256:1111111111111111111", "annotations": {}}
        img_b = {"ref": "b", "digest": "sha256:2222222222222222222", "annotations": {}}
        ldiff = {"download_bytes": 0, "total_size_b": 1000, "chunks_changed": 0,
                 "chunks_reused": 1, "chunks_b": 1, "changed_chunks": [], "download_pct": 0.0}
        verdict = {"level": "skip", "headline": "ok", "headline_zh": "正常",
                   "security_pkgs": []}
        return S.render_markdown("s", img_a, img_b, diff, ldiff, verdict, list(notes))

    def test_added_packages_are_not_reported_as_identical_nevras(self):
        diff = {"added": ["newpkg"], "removed": [], "downgrades": [], "changed": [],
                "count_a": 10, "count_b": 11}
        md = self._render(diff)
        self.assertIn("`newpkg`", md)
        self.assertNotIn("same NEVRA", md)
        self.assertNotIn("NEVRA 完全一致", md)

    def test_notes_and_package_set_changes_are_separate_items(self):
        # consecutive "> " lines - or plain lines - are ONE paragraph in Markdown,
        # so the notes and the added/removed lists used to run together
        diff = {"added": ["newpkg"], "removed": ["oldpkg"], "downgrades": [],
                "changed": [], "count_a": 10, "count_b": 10}
        md = self._render(diff, [S.T("first note", "第一条"), S.T("second note", "第二条")])
        zh, en = md.split("\n\n---\n\n")
        self.assertIn("> - first note\n> - second note\n", en)
        self.assertIn("> - 第一条\n> - 第二条\n", zh)
        self.assertIn("\n- added (1): `newpkg`\n- removed (1): `oldpkg`\n", en)
        self.assertIn("\n- 新增 (1): `newpkg`\n- 移除 (1): `oldpkg`\n", zh)


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

    def test_level_basis_names_what_raised_skip_to_consider(self):
        # Both of these raise `skip` to `consider`. The basis was empty for the
        # first and still carried the replaced `skip` sentence for the second.
        d = {"added": [], "removed": [], "downgrades": [],
             "changed": [{"name": "nano", "src": "nano", "dir": "upgrade",
                          "old": {"evr": "8.0-1"}, "new": {"evr": "8.1-1"}}],
             "count_a": 5, "count_b": 5}
        meta = {"kernel_a": "1", "kernel_b": "1"}
        xc = S.crosscheck_chunks(LD_FIX, d, {"nano": "nano"})
        v = S.verdict_of(d, LD_FIX, meta, xc, bodhi_state={"failed": 1})
        self.assertEqual(v["level"], "consider")
        self.assertIn("coverage is incomplete", v["level_basis"])
        backlog = [{"name": "openssl", "severity": "important", "want": "3.1-2",
                    "have": "3.1-1", "src": "openssl", "alias": "FEDORA-2026-x", "cves": []}]
        v = S.verdict_of(d, LD_FIX, meta, xc, backlog)
        self.assertEqual(v["level"], "consider")
        self.assertIn("still misses 1 important+", v["level_basis"])
        self.assertNotIn("no CVE", v["level_basis"])

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

    def test_silent_rebuild_of_a_versioned_source_name_is_still_important(self):
        # chunks carry the source name, which for the interpreter is python3.14
        xc = {"silent_rebuilds": [("python3.14", 5), ("nano", 4)],
              "non_package_bytes": 0, "versions_known": True}
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"}, xc)
        self.assertEqual(v["silent_important"], ["python3.14"])

    def test_no_change_headline_counts_every_moved_chunk(self):
        # 3 chunks moved; only one of them is a single-package (silent) rebuild
        ld = dict(LD_FIX, changed_chunks=[
            {"components": ["rpm/a", "rpm/b"], "size": 9},
            {"components": ["rpm/x"], "size": 5},
            {"components": ["bigfiles/initramfs.img"], "size": 3}])
        d = {"added": [], "removed": [], "downgrades": [], "changed": [],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, ld, {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(ld, d, {}))
        self.assertEqual(v["level"], "no-change")
        self.assertIn("the 3 moved chunk(s)", v["headline"])
        self.assertIn("3 个变化的 chunk", v["headline_zh"])


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

    def test_backlog_coverage_note_needs_an_audit_that_ran(self):
        # without Bodhi there is no audit: "0 of 0 candidate source packages were
        # queried" read as "nothing to check" rather than "nothing was checked"
        import types

        class Reg:
            def _token(self):
                return None

        args = types.SimpleNamespace(exact=1, keep_order=True, no_bodhi=True, audit=True,
                                     max_bodhi=0, cache_dir=None, cosign_pub=None)
        img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}
        orig = S.load_pkglist
        S.load_pkglist = lambda *a: S.PackageTable({"nano": pkg("nano", "8.0-1.fc44")})
        try:
            res = S.do_diff(args, "a", "b", images=(img, dict(img, ref="b")), reg=Reg())
        finally:
            S.load_pkglist = orig
        self.assertFalse([n for n in res["notes"] if "backlog audit coverage" in n])

    def test_multilib_note_counts_what_it_leaves_out(self):
        # a bare " …" cannot tell 1 hidden collision from 100 (see clip_list)
        import types

        class Reg:
            def _token(self):
                return None

        pb = S.PackageTable({"nano": pkg("nano", "8.0-1.fc44")})
        pb.collisions = [{"name": f"lib{i}", "kept_arch": "x86_64", "kept_evr": "1-1",
                          "shadowed_arch": "i686", "shadowed_evr": "1-1"} for i in range(6)]
        args = types.SimpleNamespace(exact=1, keep_order=True, no_bodhi=True, audit=False,
                                     max_bodhi=0, cache_dir=None, cosign_pub=None)
        img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}, "layers": []}
        orig = S.load_pkglist
        S.load_pkglist = lambda *a: pb
        try:
            res = S.do_diff(args, "a", "b", images=(img, dict(img, ref="b")), reg=Reg())
        finally:
            S.load_pkglist = orig
        note = next(n for n in res["notes"] if "multilib" in n)
        self.assertIn("+2 more not shown", note.en)
        self.assertIn("另有 2 个未显示", note.zh)

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

    def test_report_is_written_as_utf8_whatever_the_locale(self):
        # open() follows the locale, and the report is bilingual: under a
        # non-UTF-8 locale it could not be written at all
        seen = []
        real_open = open

        def spy(path, mode="r", *a, **kw):
            seen.append(kw.get("encoding"))
            return real_open(path, mode, *a, **kw)

        with tempfile.TemporaryDirectory() as d:
            S.open = spy
            try:
                S._atomic_write_text(os.path.join(d, "report.md"), "结论 / Verdict\n")
            finally:
                del S.open
        self.assertEqual(seen, ["utf-8"])

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

    def test_downgraded_sensitive_package_is_not_called_a_version_bump(self):
        cls = {"cves": [], "cves_dropped": [], "security": False, "important_src": True,
               "has_security_erratum": False, "aliases": [], "already_had": [],
               "not_pushed": [], "why": [], "erratum": None, "erratum_severity": "",
               "sev_rank": 0}
        d = {"added": [], "removed": [], "downgrades": [{"name": "openssl"}],
             "changed": [{"name": "openssl", "src": "openssl", "dir": "downgrade",
                          "old": {"evr": "3.2.1-1.fc44"}, "new": {"evr": "3.2.0-1.fc44"},
                          "cls": cls}],
             "count_a": 5, "count_b": 5}
        v = S.verdict_of(d, LD_FIX, {"kernel_a": "1", "kernel_b": "1"},
                         S.crosscheck_chunks(LD_FIX, d, {"openssl": "openssl"}))
        self.assertEqual(v["level"], "consider")
        self.assertEqual(v["important_pkgs"], [])
        self.assertNotIn("version bump", v["headline"])
        self.assertIn("downgrades openssl", v["headline"])
        self.assertEqual(v["downgrades"], ["openssl"])

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
# M - no silent truncation
# --------------------------------------------------------------------------- #
class TestNoSilentTruncation(unittest.TestCase):
    """A cut that is not marked and counted is a lie by omission: the reader
    cannot tell 2 dropped entries from 200. Every one of these used to be silent."""

    def test_clip_helpers_mark_and_count_what_they_drop(self):
        self.assertEqual(S.clip_list(["a", "b"], 5), "a, b")
        self.assertEqual(S.clip_list(["a", "b", "c"], 2), "a, b (+1 more not shown)")
        self.assertEqual(S.clip_list(range(113), 6, lang="zh", joiner="，"),
                         "0，1，2，3，4，5（另有 107 个未显示）")
        self.assertEqual(S.clip_list(["a", "b", "c"], 2, lang="both"),
                         "a, b (+1 more not shown / 另有 1 个未显示)")
        self.assertEqual(S.clip_text("short", 90), "short")
        self.assertIn("(+5 chars not shown)", S.clip_text("x" * 95, 90))
        self.assertIn("另有 5 个字符未显示", S.clip_text("x" * 95, 90, lang="zh"))
        self.assertEqual(S.clip_col("short", 15), "short")
        self.assertEqual(S.clip_col("x" * 40, 15), "x" * 14 + "…")
        self.assertEqual(S.clip_hash("sha256:" + "a" * 64, 19), "sha256:" + "a" * 12 + "…")

    def test_security_table_says_how_many_cves_it_elided(self):
        """The reported bug: 113 ids, table showed 6, nothing said the other 107
        existed (and because sorted() leads with the oldest, they were the 2026 ones)."""
        md, zh, en, _ = webkitgtk_report()
        self.assertIn("CVE-2023-4860", md)          # the ids that were shown before
        self.assertIn("(+107 more not shown)", en)
        self.assertIn("（另有 107 个未显示）", zh)

    def test_no_cve_is_dropped_from_the_report_anywhere(self):
        """Not just marked - still present. The elided ids get their own section,
        so the report never loses one."""
        md, _, _, _ = webkitgtk_report()
        for cve in WEBKITGTK_113:
            self.assertIn(cve, md, f"{cve} is missing from the report")
        self.assertIn("## CVEs the table above could not fit", md)
        self.assertIn("113 CVE(s)", md)

    def test_headline_counts_the_cves_and_groups_it_leaves_out(self):
        md, zh, en, _ = webkitgtk_report()
        self.assertIn("(+111 more not shown)", en)      # 113 - HEADLINE_CVE_CAP(2)
        self.assertIn("（另有 111 个未显示）", zh)
        # and the group cap is stated too when more than 4 source packages moved
        many = {}
        for i in range(6):
            many[f"p{i}"] = (pkg(f"p{i}", "1.0-1.fc44"), pkg(f"p{i}", "1.1-1.fc44", changelog=[
                {"time": 2, "text": f"Fix CVE-2026-90{i:03d}"}]))
        pa = {k: v[0] for k, v in many.items()}
        pb = {k: v[1] for k, v in many.items()}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        v = S.verdict_of(d, {"download_bytes": 1, "total_size_b": 1, "chunks_changed": 1,
                             "chunks_reused": 1, "chunks_a": 1, "chunks_b": 1,
                             "changed_chunks": [], "changed_packages_from_chunks": [],
                             "download_pct": 1.0},
                         {"kernel_a": "k", "kernel_b": "k"}, {})
        self.assertIn("(+2 more not shown)", v["headline"])
        self.assertIn("（另有 2 个未显示）", v["headline_zh"])

    def test_added_and_removed_lists_disclose_the_remainder(self):
        pa = {"keep": pkg("keep", "1.0-1.fc44")}
        pb = {"keep": pkg("keep", "1.0-1.fc44")}
        for i in range(45):
            pb[f"new{i}"] = pkg(f"new{i}", "1.0-1.fc44")
        d = S.pkg_diff(pa, pb)
        ld = {"download_bytes": 1, "total_size_b": 1, "chunks_changed": 0,
              "chunks_reused": 1, "chunks_a": 1, "chunks_b": 1, "changed_chunks": [],
              "changed_packages_from_chunks": [], "download_pct": 0.0}
        v = S.verdict_of(d, ld, {"kernel_a": "k", "kernel_b": "k"}, {})
        md = S.render_markdown("s", {"ref": "a", "digest": "sha256:" + "1" * 64,
                                     "annotations": {"rpmostree.inputhash": "h"}},
                               {"ref": "b", "digest": "sha256:" + "2" * 64,
                                "annotations": {"rpmostree.inputhash": "h"}},
                               d, ld, v, [])
        zh, en = md.split("\n\n---\n\n")
        self.assertIn("(+5 more not shown)", en)
        self.assertIn("（另有 5 个未显示）", zh)

    def test_backlog_table_discloses_hidden_rows(self):
        rows = [{"name": f"pkg{i}", "have": "1-1", "want": "1-2",
                 "severity": "high", "alias": f"FEDORA-2026-{i}"} for i in range(30)]
        pa = {"a": pkg("a", "1.0-1.fc44")}
        pb = {"a": pkg("a", "1.1-1.fc44")}
        d = S.pkg_diff(pa, pb)
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        ld = {"download_bytes": 1, "total_size_b": 1, "chunks_changed": 1,
              "chunks_reused": 1, "chunks_a": 1, "chunks_b": 1,
              "changed_chunks": [], "changed_packages_from_chunks": [], "download_pct": 1.0}
        v = S.verdict_of(d, ld, {"kernel_a": "k", "kernel_b": "k"}, {})
        md = S.render_markdown("s", {"ref": "a", "digest": "sha256:" + "1" * 64,
                                     "annotations": {"rpmostree.inputhash": "h"}},
                               {"ref": "b", "digest": "sha256:" + "2" * 64,
                                "annotations": {"rpmostree.inputhash": "h"}},
                               d, ld, v, [], backlog=rows)
        self.assertIn("the JSON output always carries all 30", md)
        self.assertIn("另有 5 行未显示", md)

    def test_no_join_of_a_sliced_list_is_left_unmarked(self):
        """Source tripwire: the exact shape of the reported bug was
        `", ".join(g["cves"][:6])` - a join over a sliced list with no marker."""
        path = os.path.join(os.path.dirname(HERE), "sbwatch.py")
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        for i, line in enumerate(lines):
            if "join(" not in line or not re.search(r"\[:\s*\d+\]", line):
                continue
            window = line + (lines[i + 1] if i + 1 < len(lines) else "")
            self.assertTrue(
                re.search(r"另|more|\+\{|…|\+\d", window),
                f"sbwatch.py:{i+1} joins a sliced list without saying what it cut: "
                f"{line.strip()}")

    def test_payload_lists_are_never_sliced(self):
        """cves / aliases / dropped / security_pkgs are the payload a reader acts
        on; every one of these slices was silent, so there must be none left."""
        path = os.path.join(os.path.dirname(HERE), "sbwatch.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for name in ("cves", "aliases", "dropped", "security_pkgs", "cves_dropped",
                     "added_packages_with_advisories"):
            self.assertIsNone(
                re.search(r'\["' + name + r'"\]\s*\[:', src),
                f'["{name}"][:...] is back: slice it through clip_list() instead')


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

    def test_an_inconclusive_run_still_uploads_its_report(self):
        # the failing step says "the report is already uploaded above"
        wf = self._workflow()
        step = wf.split("- name: Upload report")[1].split("- name:")[0]
        cond = re.search(r"^\s*if: (.*)$", step, re.M).group(1)
        self.assertNotIn("'unknown'", cond)


# --------------------------------------------------------------------------- #
# N - report / CLI rendering and robustness findings
# --------------------------------------------------------------------------- #
class TestDroppedMentionKeepsItsVersionLine(unittest.TestCase):
    def test_group_that_only_lost_a_cve_mention_is_still_listed_as_a_bump(self):
        old = pkg("foo", "1.0-1.fc44", "foo", [{"time": 1, "text": "- fix CVE-2025-1111"}])
        new = pkg("foo", "1.1-1.fc44", "foo", [{"time": 2, "text": "- rebase"}])
        d = S.pkg_diff({"foo": old}, {"foo": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        ld = dict(LD_FIX, chunks_changed=0, chunks_reused=1, chunks_a=1, chunks_b=1,
                  download_pct=0)
        v = S.verdict_of(d, ld, {"kernel_a": "k", "kernel_b": "k"}, {})
        img = {"ref": "a", "digest": "sha256:" + "1" * 64, "annotations": {}}
        md = S.render_markdown("s", img, img, d, ld, v, [])
        self.assertIn("no longer mentions CVE-2025-1111", md)
        self.assertIn("| foo | `foo` | 1.0-1.fc44 → 1.1-1.fc44 |", md)


class TestHistoryHeaderAlignment(unittest.TestCase):
    def test_chinese_header_lines_up_with_the_english_one(self):
        import contextlib
        import types
        import unicodedata

        def cells(s):                     # terminal cells: CJK is double-width
            return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)

        row = {"digest": "sha256:" + "a" * 64, "created": "2026-01-01T00:00:00Z",
               "version": "44.20260101.0", "inputhash": "abc", "kernel": "7.0",
               "tags": ["latest"], "from_prev": None, "same_input_as_prev": False}
        saved = S._registry, S.build_history
        S._registry = lambda args: types.SimpleNamespace(_token=lambda: None)
        S.build_history = lambda reg, **kw: [row]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                S.cmd_history(types.SimpleNamespace(image="x/y", arch="amd64", scan=1,
                                                    days=0, to="latest"))
        finally:
            S._registry, S.build_history = saved
        lines = buf.getvalue().splitlines()
        en = next(ln for ln in lines if "created (UTC)" in ln)
        zh = next(ln for ln in lines if "创建时间" in ln)
        for en_label, zh_label in (("image version", "镜像版本"), ("input", "输入哈希"),
                                   ("chunks", "chunk"), ("kernel", "内核"), ("refs", "引用")):
            self.assertEqual(cells(zh[:zh.index(zh_label)]), cells(en[:en.index(en_label)]),
                             f"column {en_label!r} is misaligned")


class TestCheckSurvivesAFailedHistoryScan(unittest.TestCase):
    def test_registry_error_in_the_history_scan_falls_back(self):
        import contextlib
        import types

        cur = {"ref": "latest", "digest": "sha256:" + "a" * 64,
               "index_digest": "sha256:" + "b" * 64, "created": "2026-01-01T00:00:00Z",
               "annotations": {}, "layers": []}

        def boom(*a, **kw):
            raise S.RegistryError("registry error 503 for x/y", http_code=503)

        saved = S._registry, S.resolve, S.build_history, S.tag_exists
        saved_env = {k: os.environ.pop(k, None) for k in ("GITHUB_OUTPUT", "GITHUB_ACTIONS")}
        S._registry = lambda args: types.SimpleNamespace(_token=lambda: None)
        S.resolve = lambda reg, ref, light=False: cur
        S.build_history = boom
        S.tag_exists = lambda reg, tag, warn=None: None
        try:
            with tempfile.TemporaryDirectory() as d, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                args = types.SimpleNamespace(
                    image="x/y", arch="amd64", to="latest", a=None, scan=12, force=False,
                    state=os.path.join(d, "state.json"), report=os.path.join(d, "report.md"))
                # no baseline can be found either, but that is a clean exit 0
                self.assertEqual(S.cmd_check(args), 0)
                self.assertTrue(os.path.exists(args.state))
        finally:
            S._registry, S.resolve, S.build_history, S.tag_exists = saved
            os.environ.update({k: v for k, v in saved_env.items() if v is not None})
        self.assertIn("history scan failed", err.getvalue())


class TestGithubOutputEncoding(unittest.TestCase):
    def test_github_output_is_written_as_utf8_whatever_the_locale(self):
        seen = []
        real_open = open

        def spy(path, mode="r", *a, **kw):
            seen.append(kw.get("encoding"))
            return real_open(path, mode, *a, **kw)

        saved_env = os.environ.get("GITHUB_OUTPUT")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "github_output")
            os.environ["GITHUB_OUTPUT"] = path
            S.open = spy
            try:
                S.gh_outputs({"summary": S.T("no new build", "无新构建")})
            finally:
                del S.open
                if saved_env is None:
                    del os.environ["GITHUB_OUTPUT"]
                else:
                    os.environ["GITHUB_OUTPUT"] = saved_env
            self.assertEqual(seen, ["utf-8"])
            with open(path, encoding="utf-8") as fh:
                self.assertIn("无新构建", fh.read())


class TestTagListCapIsReported(unittest.TestCase):
    def test_hitting_the_page_cap_is_logged_not_silent(self):
        import contextlib
        import types

        class Page:
            headers = {"Link": '</v2/x/y/tags/list?n=1000&last=t>; rel="next"'}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        reg = types.SimpleNamespace(host="h", repo="x/y", timeout=1, _token=lambda: None,
                                    _read_all=lambda r, what: b'{"tags": ["t"]}')
        real = S.urllib.request.urlopen
        S.urllib.request.urlopen = lambda req, timeout=None: Page()
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                tags = S.list_tags(reg, max_pages=3)
        finally:
            S.urllib.request.urlopen = real
        self.assertEqual(tags, ["t", "t", "t"])
        self.assertIn("capped at 3 pages", err.getvalue())

    def test_a_garbled_page_body_is_retried_not_fatal(self):
        import contextlib
        import io
        import types

        class Page:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        bodies = [b"<html>502 Bad Gateway</html>", b'{"tags": ["ok"]}']
        reg = types.SimpleNamespace(host="h", repo="x/y", timeout=1, _token=lambda: None,
                                    _read_all=lambda r, what: bodies.pop(0))
        real_open, real_sleep = S.urllib.request.urlopen, S.time.sleep
        S.urllib.request.urlopen = lambda req, timeout=None: Page()
        S.time.sleep = lambda s: None
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                tags = S.list_tags(reg, max_pages=3)
        finally:
            S.urllib.request.urlopen, S.time.sleep = real_open, real_sleep
        self.assertEqual(tags, ["ok"])
        self.assertEqual(bodies, [])


class TestGroupShowsTheSourceBuildVersion(unittest.TestCase):
    @staticmethod
    def _nss(name, evr, build):
        p = pkg(name, evr, "nss")
        p["srpm"] = "nss-" + build          # as package_list() stores it
        return p

    def test_subpackage_with_its_own_version_does_not_stand_in_for_the_source(self):
        # nspr is built from nss, carries its own Version and sorts first
        pa = {"nspr": self._nss("nspr", "4.38.0-9.fc45", "3.130.0-1.fc45"),
              "nss": self._nss("nss", "3.130.0-1.fc45", "3.130.0-1.fc45")}
        pb = {"nspr": self._nss("nspr", "4.39.0-9.fc45", "3.131.0-1.fc45"),
              "nss": self._nss("nss", "3.131.0-1.fc45", "3.131.0-1.fc45")}
        g = S.group_by_src(S.pkg_diff(pa, pb)["changed"])[0]
        self.assertEqual([p["name"] for p in g["pkgs"]], ["nspr", "nss"])
        self.assertEqual((g["old_evr"], g["new_evr"]), ("3.130.0-1.fc45", "3.131.0-1.fc45"))

    def test_entry_without_a_source_rpm_falls_back_to_its_own_evr(self):
        old, new = {"name": "x", "evr": "1-1"}, {"name": "x", "evr": "1-2"}
        g = S.group_by_src([{"name": "x", "src": "x", "old": old, "new": new}])[0]
        self.assertEqual((g["old_evr"], g["new_evr"]), ("1-1", "1-2"))


class TestCosignRunsOncePerDigest(unittest.TestCase):
    """`check` verifies the image it watches and do_diff() then reports on that
    same digest. A digest names immutable content, so the second cosign round trip
    (up to its 90 s timeout when cosign hangs) answered a question already asked."""

    DIG = "sha256:" + "a" * 64

    def setUp(self):
        import types
        S._COSIGN_RESULTS.clear()
        self.calls = []
        self.verdict = True
        self._saved = S.verify_cosign_image
        S.verify_cosign_image = self._fake
        self.reg = types.SimpleNamespace(host="ghcr.io", repo="x/y")

    def tearDown(self):
        S.verify_cosign_image = self._saved
        S._COSIGN_RESULTS.clear()

    def _fake(self, ref, pub, require=False):
        self.calls.append((ref, pub, require))
        return self.verdict

    @staticmethod
    def _args(require=False):
        import types
        return types.SimpleNamespace(cosign_pub="k/cosign.pub", require_cosign=require)

    def test_same_digest_is_verified_once_but_reported_every_time(self):
        notes = []
        for _ in range(2):
            self.assertTrue(S.maybe_verify_resolved(
                self.reg, {"digest": self.DIG}, self._args(), notes))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(notes), 2, "each report must still state the outcome")

    def test_a_tolerated_failure_is_remembered_too(self):
        self.verdict = False
        notes = []
        for _ in range(2):
            self.assertFalse(S.maybe_verify_resolved(
                self.reg, {"digest": self.DIG}, self._args(), notes))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all("FAILED" in str(n) for n in notes))

    def test_another_digest_or_policy_is_never_answered_from_the_cache(self):
        S.maybe_verify_resolved(self.reg, {"digest": self.DIG}, self._args())
        S.maybe_verify_resolved(self.reg, {"digest": "sha256:" + "b" * 64}, self._args())
        S.maybe_verify_resolved(self.reg, {"digest": self.DIG}, self._args(require=True))
        self.assertEqual(len(self.calls), 3)


class TestHistoryReusesTheResolvedImage(unittest.TestCase):
    """`check` has already resolved (and signature-checked) `--to`; resolving it
    again cost three registry round trips and could anchor the history on a
    different build if the tag moved in between."""

    CUR = {"ref": "latest", "digest": "sha256:" + "a" * 64,
           "index_digest": "sha256:" + "b" * 64, "created": "2026-01-01T00:00:00Z",
           "annotations": {"org.opencontainers.image.version": "44.20260101.0"},
           "layers": [], "total_size": 0}

    def test_build_history_does_not_resolve_the_current_tag_again(self):
        import types
        asked = []

        def fake_resolve(reg, ref, light=False):
            asked.append(ref)
            raise AssertionError(f"unexpected resolve({ref!r})")

        saved = S.resolve, S.list_tags
        S.resolve, S.list_tags = fake_resolve, lambda reg, max_pages=12: []
        try:
            rows = S.build_history(types.SimpleNamespace(), scan=3, days=0, to="latest",
                                   cur=self.CUR)
        finally:
            S.resolve, S.list_tags = saved
        self.assertEqual(asked, [])
        self.assertEqual([r["digest"] for r in rows], [self.CUR["index_digest"]])

    def test_without_cur_it_still_resolves_the_tag_itself(self):
        import types
        saved = S.resolve, S.list_tags
        S.resolve, S.list_tags = (lambda reg, ref, light=False: dict(self.CUR, ref=ref),
                                  lambda reg, max_pages=12: [])
        try:
            rows = S.build_history(types.SimpleNamespace(), scan=3, days=0, to="latest")
        finally:
            S.resolve, S.list_tags = saved
        self.assertEqual(len(rows), 1)

    def test_check_hands_its_image_to_the_history_scan(self):
        import contextlib
        import types
        got = {}

        def fake_history(reg, **kw):
            got.update(kw)
            return []

        saved = S._registry, S.resolve, S.build_history, S.tag_exists
        saved_env = {k: os.environ.pop(k, None) for k in ("GITHUB_OUTPUT", "GITHUB_ACTIONS")}
        S._registry = lambda args: types.SimpleNamespace(_token=lambda: None)
        S.resolve = lambda reg, ref, light=False: self.CUR
        S.build_history = fake_history
        S.tag_exists = lambda reg, tag, warn=None: None
        try:
            with tempfile.TemporaryDirectory() as d, \
                    contextlib.redirect_stderr(io.StringIO()):
                args = types.SimpleNamespace(
                    image="x/y", arch="amd64", to="latest", a=None, scan=12, force=False,
                    state=os.path.join(d, "state.json"), report=os.path.join(d, "report.md"))
                S.cmd_check(args)
        finally:
            S._registry, S.resolve, S.build_history, S.tag_exists = saved
            os.environ.update({k: v for k, v in saved_env.items() if v is not None})
        self.assertIs(got.get("cur"), self.CUR)


class TestTagLabelCostsOneRequest(unittest.TestCase):
    """Labelling a history row with a dated tag only needs the digest the tag
    points at - not the platform manifest resolve() fetches after the index."""

    DIG = "sha256:" + "c" * 64

    class _Resp:
        def __init__(self, headers, body=b""):
            self.headers, self._body = headers, body

        def read(self, n=-1):
            b, self._body = self._body, b""
            return b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _reg(self, headers, body=b""):
        reg = S.Registry.__new__(S.Registry)
        reg.paths = []

        def fake_open(path, accept):
            reg.paths.append(path)
            return self._Resp(headers, body)

        reg._open = fake_open
        return reg

    def test_digest_comes_from_the_header_in_a_single_request(self):
        reg = self._reg({"Docker-Content-Digest": self.DIG})
        self.assertEqual(reg.index_digest("20260917"), self.DIG)
        self.assertEqual(reg.paths, ["manifests/20260917"])

    def test_without_the_header_it_hashes_the_manifest_like_resolve_does(self):
        import hashlib
        reg = self._reg({}, b'{"manifests": []}')
        self.assertEqual(reg.index_digest("t"),
                         "sha256:" + hashlib.sha256(b'{"manifests": []}').hexdigest())

    def test_tag_exists_hashes_the_manifest_when_the_header_is_missing(self):
        import hashlib
        reg = self._reg({"Docker-Content-Digest": self.DIG})
        self.assertEqual(S.tag_exists(reg, "20260917"), self.DIG)
        reg = self._reg({}, b'{"manifests": []}')
        warn = []
        self.assertEqual(S.tag_exists(reg, "20260917", warn=warn),
                         "sha256:" + hashlib.sha256(b'{"manifests": []}').hexdigest())
        self.assertEqual(warn, [])

    def test_tag_exists_warns_instead_of_exiting_when_the_body_read_fails(self):
        import contextlib
        import io
        reg = self._reg({}, b"")

        def broken(resp, what):
            raise SystemExit("failed reading " + what)

        reg._read_all = broken
        warn = []
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(S.tag_exists(reg, "20260917", warn=warn))
        self.assertEqual(len(warn), 1)

    def test_history_labels_rows_without_resolving_dated_tags(self):
        cur = dict(TestHistoryReusesTheResolvedImage.CUR)
        probed = []

        class FakeReg:
            host, repo, timeout, arch = "ghcr.io", "secureblue/x", 30, "amd64"

            def _token(self):
                return "t"

            def index_digest(self, ref):
                probed.append(ref)
                return cur["index_digest"]

        def fake_resolve(reg, ref, light=False):
            raise AssertionError(f"dated tag {ref!r} must not be fully resolved")

        saved = S.resolve, S.list_tags
        S.resolve = fake_resolve
        S.list_tags = lambda reg, max_pages=12: ["20260101", "20260101-44", "latest-uki"]
        try:
            rows = S.build_history(FakeReg(), scan=3, days=1, to="latest", cur=cur)
        finally:
            S.resolve, S.list_tags = saved
        self.assertEqual(probed, ["20260101", "20260101-44"])
        self.assertEqual(rows[0]["tags"], ["latest", "20260101", "20260101-44"])


class TestPackageListStreamsTheRpmdb(unittest.TestCase):
    """package_list() must not fetchall() the Packages table: the header blobs are
    most of the ~92 MiB database and only the one being parsed has to be in memory."""

    @staticmethod
    def _blob(name, version):
        import struct
        ents = [(1000, name), (1001, version), (1002, "1.fc44"), (1022, "x86_64")]
        store, index = b"", b""
        for tag, val in ents:
            index += struct.pack(">IIII", tag, 6, len(store), 1)
            store += val.encode() + b"\0"
        return struct.pack(">II", len(ents), len(store)) + index + store

    def _db(self, d, create=True):
        import sqlite3
        path = os.path.join(d, "rpmdb.sqlite")
        con = sqlite3.connect(path)
        if create:
            con.execute("create table Packages (hnum integer primary key, blob blob)")
            con.executemany("insert into Packages (blob) values (?)",
                            [(self._blob("foo", "1.0"),), (self._blob("bar", "2.0"),)])
        else:
            con.execute("create table Other (x)")
        con.commit()
        con.close()
        return path

    class _Spy:
        """Wraps the connection so that fetchall() on its cursor is a failure."""

        def __init__(self, con):
            self._con, self.closed = con, False

        def execute(self, sql):
            cur = self._con.execute(sql)

            class Cur:
                def fetchall(self_inner):
                    raise AssertionError("package_list() must iterate, not fetchall()")

                def __iter__(self_inner):
                    return iter(cur)
            return Cur()

        def close(self):
            self.closed = True
            self._con.close()

    def _run(self, create=True):
        chunk = {"digest": "sha256:" + "d" * 64, "size": 1,
                 "components": ["bigfiles/rpmdb.sqlite"]}
        with tempfile.TemporaryDirectory() as d:
            path = self._db(d, create)

            class FakeReg:
                def extract_member(self_inner, layer, match):
                    return path

            spies = []
            real = S.sqlite3.connect

            def spy_connect(*a, **kw):
                spies.append(self._Spy(real(*a, **kw)))
                return spies[-1]

            S.sqlite3.connect = spy_connect
            try:
                try:
                    out = S.package_list(FakeReg(), {"layers": [chunk]})
                except SystemExit as e:
                    out = e
            finally:
                S.sqlite3.connect = real
            return out, spies[0], os.path.exists(path)

    def test_rows_are_streamed_and_the_database_is_cleaned_up(self):
        pkgs, spy, still_there = self._run()
        self.assertEqual(sorted(pkgs), ["bar", "foo"])
        self.assertEqual(pkgs["foo"]["evr"], "1.0-1.fc44")
        self.assertTrue(spy.closed)
        self.assertFalse(still_there, "the extracted rpmdb must be deleted after parsing")

    def test_missing_packages_table_is_still_a_clean_error(self):
        err, spy, _ = self._run(create=False)
        self.assertIsInstance(err, SystemExit)
        self.assertIn("rpmdb", str(err))
        self.assertTrue(spy.closed)


class TestExplicitFromTagRunsOnAnUnchangedDigest(unittest.TestCase):
    """The workflow's `from_tag` is passed as `--a`: it asks for that comparison,
    which "no new build since the last look" does not answer."""

    class _Reached(Exception):
        pass

    def _check(self, a):
        import contextlib
        import types
        cur = {"ref": "latest", "digest": "sha256:" + "a" * 64,
               "index_digest": "sha256:" + "b" * 64, "created": "2026-01-01T00:00:00Z",
               "annotations": {"org.opencontainers.image.version": "44.20260101.0"},
               "layers": []}
        reached = []

        def fake_diff(*args, **kw):
            reached.append(args[1])
            raise self._Reached()

        saved = S._registry, S.resolve, S.do_diff
        saved_env = {k: os.environ.pop(k, None) for k in ("GITHUB_OUTPUT", "GITHUB_ACTIONS")}
        S._registry = lambda args: types.SimpleNamespace(_token=lambda: None)
        S.resolve = lambda reg, ref, light=False: dict(cur, ref=ref)
        S.do_diff = fake_diff
        try:
            with tempfile.TemporaryDirectory() as d, \
                    contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                state = os.path.join(d, "state.json")
                with open(state, "w") as fh:
                    json.dump({"digest": cur["digest"], "created": cur["created"]}, fh)
                args = types.SimpleNamespace(
                    image="x/y", arch="amd64", to="latest", a=a, scan=0, force=False, fast=False,
                    state=state, report=os.path.join(d, "report.md"))
                try:
                    rc = S.cmd_check(args)
                except self._Reached:
                    rc = "diff"
        finally:
            S._registry, S.resolve, S.do_diff = saved
            os.environ.update({k: v for k, v in saved_env.items() if v is not None})
        return rc, reached

    def test_explicit_a_runs_the_comparison(self):
        rc, reached = self._check("20251231")
        self.assertEqual(rc, "diff")
        self.assertEqual(reached, ["20251231"])

    def test_without_a_an_unchanged_digest_is_still_skipped(self):
        rc, reached = self._check(None)
        self.assertEqual(rc, 0)
        self.assertEqual(reached, [])


class TestSecurityTableSurvivesAPipeInTheEvidence(unittest.TestCase):
    """The first line of a changelog entry lands in the evidence cell verbatim;
    a bare `|` ended the cell early and shifted every column after it."""

    def _security_rows(self):
        old = pkg("libfoo", "1.0-1.fc44", "libfoo", [{"time": 1, "text": "- 1.0"}])
        new = pkg("libfoo", "1.1-1.fc44", "libfoo", [
            {"time": 1, "text": "- 1.0"},
            {"time": 2, "text": "Security fix for CVE-2026-1111: bad parse of a|b|c input"}])
        d = S.pkg_diff({"libfoo": old}, {"libfoo": new})
        for c in d["changed"]:
            c["cls"] = S.classify_change(c["old"], c["new"], "F44", None)
        ld = {"download_bytes": 1, "total_size_b": 1, "chunks_changed": 1,
              "chunks_reused": 1, "chunks_a": 1, "chunks_b": 1, "changed_chunks": [],
              "changed_packages_from_chunks": [], "download_pct": 1.0}
        v = S.verdict_of(d, ld, {"kernel_a": "k", "kernel_b": "k"}, {})
        ia = {"ref": "a", "digest": "sha256:" + "1" * 64,
              "annotations": {"rpmostree.inputhash": "h"}}
        ib = {"ref": "b", "digest": "sha256:" + "2" * 64,
              "annotations": {"rpmostree.inputhash": "h"}}
        md = S.render_markdown("s", ia, ib, d, ld, v, [])
        return [ln for ln in md.splitlines() if ln.startswith("|") and "CVE-2026-1111" in ln
                and "bad parse" in ln]

    def test_pipes_in_the_evidence_are_escaped(self):
        rows = self._security_rows()
        self.assertTrue(rows, "the security table row was not rendered")
        for row in rows:
            self.assertIn("a\\|b\\|c", row)
            # 4 cells => 5 unescaped column separators, whatever the evidence says
            self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 5, row)


class TestClipTextHonoursBoth(unittest.TestCase):
    """clip_list() has always had a bilingual marker for strings shown in both
    halves at once; clip_text() silently fell back to English for lang="both"."""

    def test_both_marks_the_cut_in_both_languages(self):
        out = S.clip_text("x" * 95, 90, lang="both")
        self.assertIn("(+5 chars not shown", out)
        self.assertIn("另有 5 个字符未显示", out)

    def test_en_and_zh_are_unchanged(self):
        self.assertTrue(S.clip_text("x" * 95, 90).endswith("(+5 chars not shown)"))
        self.assertNotIn("另有", S.clip_text("x" * 95, 90))
        self.assertNotIn("not shown", S.clip_text("x" * 95, 90, lang="zh"))

    def test_the_english_half_of_a_note_does_not_carry_chinese(self):
        # cmd_check's "not the only new one" note builds its English half from
        # clip_text(seen, 16); the Chinese half has its own lang='zh' call
        src = open(os.path.join(os.path.dirname(HERE), "sbwatch.py"), encoding="utf-8").read()
        self.assertNotIn("clip_text(seen, 16, lang='both')", src)


WORKFLOW = os.path.join(os.path.dirname(HERE), ".github", "workflows", "sbwatch.yml")


def workflow_python(step):
    """The first `python3 - <<'PY'` heredoc of the named workflow step, dedented."""
    import textwrap
    with open(WORKFLOW, encoding="utf-8") as fh:
        wf = fh.read()
    start = wf.index(f"- name: {step}")
    end = wf.find("\n      - name:", start + 1)
    block = wf[start:end if end != -1 else len(wf)]
    m = re.search(r"python3 - <<'PY'\n(.*?)\n\s*PY\n", block, re.S)
    return textwrap.dedent(m.group(1))


class TestTelegramPush(unittest.TestCase):
    """Telegram answers HTTP 400 to a text over 4096 characters. The report is
    bilingual and a busy update's summary alone is long, so a fixed slice of the
    report plus the summary could cross the limit."""

    def _push(self, report, summary="[UPDATE-NOW] summary", reply=b'{"ok":true}'):
        import contextlib
        code = workflow_python("Push to Telegram")
        sent = {}

        class Resp:
            def read(self_inner):
                return reply

        def fake_urlopen(req, timeout=None):
            sent.update(json.loads(req.data.decode("utf-8")))
            return Resp()

        saved = S.urllib.request.urlopen
        saved_env = dict(os.environ)
        cwd = os.getcwd()
        S.urllib.request.urlopen = fake_urlopen
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1",
                           "SUMMARY": summary})
        err = io.StringIO()
        try:
            with tempfile.TemporaryDirectory() as d:
                os.chdir(d)
                with open("report.md", "w", encoding="utf-8") as fh:
                    fh.write(report)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    exec(compile(code, "telegram-step", "exec"), {"__name__": "__main__"})
        finally:
            os.chdir(cwd)
            S.urllib.request.urlopen = saved
            os.environ.clear()
            os.environ.update(saved_env)
        return sent.get("text"), err.getvalue()

    def test_a_long_report_is_cut_to_fit_and_says_so(self):
        text, _ = self._push("更新" * 6000, summary="S" * 1500)
        self.assertLessEqual(len(text), 4096)
        self.assertTrue(text.startswith("S" * 1500), "the summary must always survive")
        self.assertIn("full report in the run summary", text)

    def test_a_report_that_fits_is_sent_whole(self):
        body = "x" * 4000
        text, _ = self._push(body, summary="sum")
        self.assertEqual(text, "sum\n\n" + body)

    def test_a_missing_report_is_not_fatal(self):
        text, err = self._push("", summary="sum")
        self.assertEqual(text, "sum\n\n")
        self.assertNotIn("failed", err)


class TestTelegramReplyLogging(unittest.TestCase):
    def test_a_delivered_push_is_not_logged_as_failed_on_a_split_character(self):
        # the first 150 bytes of a reply naming a CJK chat end inside a character
        reply = ('{"ok":true,"result":{"chat":{"title":"' + "测试" * 60 + '"}}}').encode("utf-8")
        with self.assertRaises(UnicodeDecodeError):
            reply[:150].decode()                      # what the step used to do
        text, err = TestTelegramPush()._push("report", reply=reply)
        self.assertEqual(text, "[UPDATE-NOW] summary\n\nreport")
        self.assertNotIn("Telegram push failed", err)


class TestStickyIssueBodyLimit(unittest.TestCase):
    """GitHub refuses an issue/comment body over 65536 characters; the step used to
    fail on a big update and took the Telegram push after it down too."""

    def _trim(self, body):
        code = workflow_python("Comment on (or open) a sticky issue")
        cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as d:
                os.chdir(d)
                with open("body.md", "w", encoding="utf-8") as fh:
                    fh.write(body)
                exec(compile(code, "issue-step", "exec"), {"__name__": "__main__"})
                with open("body.md", encoding="utf-8") as fh:
                    return fh.read()
        finally:
            os.chdir(cwd)

    def test_a_body_under_the_limit_is_untouched(self):
        body = "更" * 65000
        self.assertEqual(self._trim(body), body)

    def test_an_oversized_body_is_cut_under_the_limit_and_says_so(self):
        for n in (65001, 70000, 300000):
            out = self._trim("更" * n)
            self.assertLessEqual(len(out), 65536, n)
            self.assertIn("chars not shown", out)
            self.assertIn(f"+{n - 64800} chars", out)


def rpm_header(entries, magic=False):
    """Build an rpm header blob: (tag, type, bytes) entries, optionally with the
    8-byte magic/version/reserved prefix (8e ad e8 01 00 00 00 00)."""
    import struct
    store, index = b"", b""
    for tag, typ, val in entries:
        index += struct.pack(">IIII", tag, typ, len(store), 1)
        store += val
    body = struct.pack(">II", len(entries), len(store)) + index + store
    return (b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + body) if magic else body


class TestMagicPrefixedRpmHeader(unittest.TestCase):
    """magic(3) + version(1) + reserved(4) is 8 bytes, then nindex and hlen: the
    index starts at 16, not at 20."""

    ENTRIES = [(1000, 6, b"foo\0"), (1001, 6, b"1.2\0")]

    def test_magic_prefixed_header_parses_like_the_bare_one(self):
        bare = S.read_header(rpm_header(self.ENTRIES))
        self.assertEqual(bare, {"name": "foo", "version": "1.2"})
        stats = {}
        self.assertEqual(S.read_header(rpm_header(self.ENTRIES, magic=True), stats), bare)
        self.assertEqual(stats, {})

    def test_a_truncated_magic_prefix_is_rejected_and_counted(self):
        stats = {}
        self.assertEqual(S.read_header(b"\x8e\xad\xe8\x01\x00\x00\x00\x00\x00\x00", stats), {})
        self.assertEqual(stats["headers_rejected"], 1)


class TestRpmHeaderIndexMustFit(unittest.TestCase):
    def test_an_index_running_past_the_blob_is_rejected_not_a_crash(self):
        import struct
        # two index entries are announced (32 bytes) but only 24 follow; hlen = 0
        # keeps the old "+40 slack" test happy, and the unguarded entry unpack
        # then raised struct.error out of the whole package-list parse
        blob = struct.pack(">II", 2, 0) + struct.pack(">IIII", 1000, 6, 0, 1) + b"\0" * 8
        stats = {}
        self.assertEqual(S.read_header(blob, stats), {})
        self.assertEqual(stats["headers_rejected"], 1)

    def test_a_complete_index_with_a_short_store_still_gets_the_slack(self):
        blob = rpm_header([(1000, 6, b"foo\0")])
        self.assertEqual(S.read_header(blob)["name"], "foo")


class TestHistorySkipsPushesWithoutTheArch(unittest.TestCase):
    """resolve() raised a bare SystemExit for an index with no manifest for --arch;
    build_history() only catches Exception/RegistryError, so one old push without
    arm64 ended the whole scan (and, in `check`, the run)."""

    GOOD = "sha256:" + "1" * 64
    NOARCH = "sha256:" + "2" * 64

    def _image(self, ref):
        return {"ref": ref, "is_index": True, "index_digest": ref, "digest": "sha256:" + "9" * 64,
                "created": "2026-01-01T00:00:00Z", "layers": [], "total_size": 0,
                "annotations": {"org.opencontainers.image.version": "44.20260101.0"}}

    def test_no_arch_manifest_is_a_registry_error_without_an_http_code(self):
        e = S.NoArchManifest("no arm64 manifest in x/y:latest")
        self.assertIsInstance(e, S.RegistryError)
        self.assertIsInstance(e, SystemExit)
        self.assertIsNone(e.http_code)

    def test_one_push_without_the_arch_does_not_abort_the_scan(self):
        import types
        cur = dict(self._image("latest"), index_digest="sha256:" + "f" * 64)

        def fake_resolve(reg, ref, light=False):
            if ref == self.NOARCH:
                raise S.NoArchManifest(f"no arm64 manifest in x/y:{ref}")
            return self._image(ref)

        warns = []
        saved = S.resolve, S.list_tags
        S.resolve = fake_resolve
        # newest sig tag last: the push without the arch is the first one visited
        S.list_tags = lambda reg, max_pages=12: [
            "sha256-" + self.GOOD.split(":")[1] + ".sig",
            "sha256-" + self.NOARCH.split(":")[1] + ".sig"]
        try:
            rows = S.build_history(types.SimpleNamespace(), scan=3, days=0, to="latest",
                                   warn=warns, cur=cur)
        finally:
            S.resolve, S.list_tags = saved
        self.assertEqual(sorted(r["digest"] for r in rows), sorted([cur["index_digest"], self.GOOD]))
        self.assertEqual(warns, [], "a push without this arch is not a probe failure")


class TestCorruptGzipBlobIsACleanError(unittest.TestCase):
    """A gzip stream with a valid header but a damaged deflate body raises
    zlib.error, which is neither OSError nor BadGzipFile: fetch_blob() let it
    escape as a raw traceback instead of its bilingual SystemExit."""

    def test_damaged_deflate_body_exits_with_a_message(self):
        import gzip
        import types
        good = bytearray(gzip.compress(os.urandom(4096) * 4))
        for i in range(20, 60):
            good[i] ^= 0xFF
        body = bytes(good)

        class Resp:
            headers = {}

            def __init__(self):
                self._i = 0

            def read(self, n=-1):
                chunk, self._i = body[self._i:self._i + n], self._i + n
                return chunk

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        reg = types.SimpleNamespace(_open=lambda path, accept: Resp())
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as cm:
                S.Registry.fetch_blob(reg, "sha256:" + "a" * 64, os.path.join(d, "x"))
        self.assertIn("failed to read/decompress layer", str(cm.exception))


class TestIdenticalRpmdbIsLoadedOnce(unittest.TestCase):
    """--exact 1 with two images that share the rpmdb chunk used to fetch and
    parse that one blob twice."""

    @staticmethod
    def _img(ref, digest, rpmdb):
        return {"ref": ref, "digest": digest, "created": "2026-09-20T00:00:00Z",
                "annotations": {}, "layers": [
                    {"digest": rpmdb, "size": 100, "components": ["bigfiles/rpmdb.sqlite"],
                     "stability": 0}]}

    def _run(self, rpmdb_a, rpmdb_b):
        import types

        class Reg:
            def _token(self):
                return None

        calls = []

        def fake_load(reg, img, ref, cache_dir, notes):
            calls.append(ref)
            return S.PackageTable({"nano": pkg("nano", "8.0-1.fc44")})

        args = types.SimpleNamespace(exact=1, keep_order=True, no_bodhi=True, audit=False,
                                     max_bodhi=0, cache_dir=None, cosign_pub=None)
        a = self._img("a", "sha256:" + "1" * 64, rpmdb_a)
        b = self._img("b", "sha256:" + "2" * 64, rpmdb_b)
        orig = S.load_pkglist
        S.load_pkglist = fake_load
        try:
            res = S.do_diff(args, "a", "b", images=(a, b), reg=Reg())
        finally:
            S.load_pkglist = orig
        return calls, res

    def test_same_chunk_loads_the_package_list_once(self):
        calls, res = self._run("sha256:same", "sha256:same")
        self.assertEqual(calls, ["a"])
        self.assertEqual(res["verdict"]["level"], "no-change")
        self.assertEqual(res["diff"]["count_b"], 1)

    def test_different_chunks_still_load_both(self):
        calls, _ = self._run("sha256:one", "sha256:two")
        self.assertEqual(calls, ["a", "b"])


class TestMissingEntriesShortCircuits(unittest.TestCase):
    A = {"time": 1, "who": "x", "text": "one"}
    B = {"time": 1, "who": "x", "text": "two"}

    def test_empty_sides(self):
        self.assertEqual(S._missing_entries([], [self.A]), [])
        self.assertEqual(S._missing_entries([self.A, self.B], []), [self.A, self.B])
        self.assertEqual(S._missing_entries([], []), [])

    def test_multiplicity_is_still_counted(self):
        self.assertEqual(S._missing_entries([self.A, self.A, self.B], [self.A]),
                         [self.A, self.B])


class TestTagsProbeIncludesToday(unittest.TestCase):
    def test_probe_starts_with_today_and_covers_exactly_days_days(self):
        import time
        import types
        probed = []
        saved = (S._registry, S.resolve, S.maybe_verify_resolved, S.tag_exists, time.time)
        S._registry = lambda args: types.SimpleNamespace(_token=lambda: None)
        S.resolve = lambda reg, ref, light=False: {
            "digest": "sha256:" + "1" * 64, "index_digest": "sha256:" + "2" * 64,
            "annotations": {}, "layers": [], "created": ""}
        S.maybe_verify_resolved = lambda *a, **k: False
        S.tag_exists = lambda reg, tag, warn=None: probed.append(tag)
        time.time = lambda: 1789776000          # 2026-09-19T00:00:00Z
        try:
            S.cmd_tags(types.SimpleNamespace(to="latest", days=3))
        finally:
            S._registry, S.resolve, S.maybe_verify_resolved, S.tag_exists, time.time = saved
        self.assertEqual(probed, ["20260919", "20260918", "20260917"])


class TestImageTagIsTheDefaultRef(unittest.TestCase):
    """`--image ns/name:44` parsed the tag into Registry.default_ref and then every
    command looked at `latest` anyway. The image's tag is now the fallback for
    --to / ref; an explicit option still wins."""

    def _args(self, image, **kw):
        import types
        return types.SimpleNamespace(image=image, arch="amd64", **kw)

    def test_tag_in_image_fills_an_unset_to(self):
        a = self._args("secureblue/x:44", to=None)
        reg = S._registry(a)
        reg.close()
        self.assertEqual(a.to, "44")

    def test_explicit_to_and_plain_image_keep_their_values(self):
        a = self._args("secureblue/x:44", to="20260917")
        S._registry(a).close()
        self.assertEqual(a.to, "20260917")
        a = self._args("secureblue/x", ref=None)
        S._registry(a).close()
        self.assertEqual(a.ref, "latest")

    def test_parsers_default_to_none_so_the_fallback_can_apply(self):
        saved = S.cmd_tags, S.cmd_check, S.cmd_backlog
        seen = {}
        S.cmd_tags = S.cmd_check = S.cmd_backlog = lambda args: seen.update(vars(args))
        try:
            S.main(["tags"])
            self.assertIsNone(seen["to"])
            S.main(["backlog"])
            self.assertIsNone(seen["ref"])
            S.main(["check", "--to", "44"])
            self.assertEqual(seen["to"], "44")
        finally:
            S.cmd_tags, S.cmd_check, S.cmd_backlog = saved


class TestHumanSizes(unittest.TestCase):
    def test_values_that_round_to_1024_move_up_a_unit(self):
        self.assertEqual(S.human(1023.99), "1.0 KiB")
        self.assertEqual(S.human(1048575.9), "1.0 MiB")
        self.assertEqual(S.human(-1023.96), "-1.0 KiB")

    def test_ordinary_values_are_unchanged(self):
        self.assertEqual(S.human(0), "0.0 B")
        self.assertEqual(S.human(1023), "1023.0 B")
        self.assertEqual(S.human(1024), "1.0 KiB")
        self.assertEqual(S.human(33 * 1024 * 1024), "33.0 MiB")
        self.assertEqual(S.human(4 * 1024 ** 4), "4.0 TiB")


if __name__ == "__main__":
    unittest.main(verbosity=2)
