"""The installed Fedora release RPM, not a rebuild plurality, identifies the OS."""
import unittest
from test_sbwatch import S, pkg


class TestReleaseIdentity(unittest.TestCase):
    def inventory(self):
        # Actual name/EVR/SRPM identity in the independently fetched 2026-11-22 image.
        release = dict(pkg("fedora-release-common", "45-14", src="fedora-release"),
                       vendor="Fedora Project")
        carried = {f"carried-{i}": dict(pkg(f"carried-{i}", "1-1.fc44"),
                                       vendor="Fedora Project") for i in range(5)}
        return {release["name"]: release, **carried}

    def test_release_identity_beats_carried_over_dist_tags_and_annotation(self):
        self.assertEqual(S.fedora_release(self.inventory(), "44.20260101.0"), "F45")

    def test_variant_release_subpackage_is_also_authoritative(self):
        packages = self.inventory()
        release = packages.pop("fedora-release-common")
        release["name"] = "fedora-release-silverblue"
        packages[release["name"]] = release
        self.assertEqual(S.fedora_release(packages), "F45")

    def test_third_party_release_does_not_override_fedora_inventory(self):
        packages = self.inventory()
        packages["fedora-release-common"]["vendor"] = "Fedora Copr - user example"
        self.assertEqual(S.fedora_release(packages), "F44")

    def test_non_numeric_or_conflicting_release_identity_uses_fallback(self):
        packages = self.inventory()
        packages["fedora-release-common"]["version"] = "rawhide"
        self.assertEqual(S.fedora_release(packages), "F44")
        packages = self.inventory()
        packages["fedora-release"] = dict(pkg("fedora-release", "44-1"), vendor="Fedora Project")
        self.assertEqual(S.fedora_release(packages), "F44")
