"""Bodhi NVRs identify Koji builds, not arbitrary binaries in their payloads."""
import unittest

import sbwatch as S


class Updates:
    failed = skipped = 0

    def __init__(self, *nvrs):
        self.nvrs = nvrs

    def updates_for_src(self, src, release):
        return [{"nvrs": self.nvrs, "alias": "FEDORA-test", "type": "security",
                 "status": "stable", "severity": "high", "notes": ""}]


# Installed in GHCR platform 0f72f71f1e72...; the two EVRs genuinely differ.
NSPR = {"name": "nspr", "src": "nss", "version": "4.39.0", "release": "10.fc45",
        "srpm": "nss-3.133.0-1.fc45", "evr": "4.39.0-10.fc45", "vendor": "Fedora Project"}


class TestBodhiSourceIdentity(unittest.TestCase):
    def test_bundled_build_with_binary_name_does_not_count(self):
        errata = Updates("nspr-4.39.0-10.fc45", "nss-3.132.0-1.fc45")
        self.assertFalse(S.classify_change(None, NSPR, "F45", errata)["security"])
        self.assertTrue(S.classify_change(None, NSPR, "F45", Updates(NSPR["srpm"]))["security"])

    def test_backlog_compares_source_even_if_subpackage_is_newer(self):
        rows, _ = S.security_backlog({"nspr": NSPR}, "F45", Updates(
            "nss-3.134.0-1.fc45", "nspr-99-1.fc45"))
        self.assertEqual([(r["have"], r["want"]) for r in rows],
                         [("3.133.0-1.fc45", "3.134.0-1.fc45")])

    def test_passed_over_uses_dist_tag_from_source_release(self):
        old = dict(NSPR, release="10", srpm="nss-3.131.0-1.fc45")
        self.assertEqual(S._passed_build(old, NSPR, ["nss-3.132.0-1.fc45"]),
                         "nss-3.132.0-1.fc45")
