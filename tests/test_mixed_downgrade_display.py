"""Source groups with mixed binary directions must label actual downgrades."""
import unittest
from test_sbwatch import S, pkg


class TestMixedDowngradeDisplay(unittest.TestCase):
    def result(self):
        old = {"nss": pkg("nss", "3.128.0-1.fc45"),
               "nspr": pkg("nspr", "4.39.0-10.fc45", src="nss")}
        new = {"nss": pkg("nss", "3.133.0-1.fc45"),
               "nspr": pkg("nspr", "4.38.0-1.fc45", src="nss")}
        for name in old:
            old[name]["srpm"] = "nss-3.128.0-1.fc45"
            new[name]["srpm"] = "nss-3.133.0-1.fc45"
        diff = S.pkg_diff(old, new)
        for change in diff["changed"]:
            change["cls"] = S.classify_change(change["old"], change["new"], "F45", None)
        layers = S.layer_diff({"layers": []}, {"layers": []})
        verdict = S.verdict_of(diff, layers, {})
        image = {"ref": "test", "digest": "sha256:" + "a" * 64, "annotations": {}}
        return verdict, S.render_markdown("mixed", image, image, diff, layers, verdict, [])

    def test_headline_counts_and_names_only_downgraded_binaries(self):
        verdict, _ = self.result()
        self.assertIn("(1 binary) downgraded", verdict["headline"])
        self.assertIn("(1 binary) bumped", verdict["headline"])
        warning = verdict["headline"].split("WARNING:")[1]
        self.assertIn("nspr (4.39.0-10.fc45", warning)
        self.assertNotIn("nss (3.128.0-1.fc45", warning)

    def test_downgrade_section_shows_binary_evr_not_ascending_source_evr(self):
        _, markdown = self.result()
        section = markdown.split("## Downgrades in this update")[1].split("\n## ")[0]
        self.assertIn("`nspr`: 4.39.0-10.fc45 → 4.38.0-1.fc45", section)
        self.assertNotIn("3.128.0-1.fc45 → 3.133.0-1.fc45", section)

    def test_upgraded_siblings_of_mixed_groups_stay_visible_in_report(self):
        _, markdown = self.result()
        en = markdown.split("\n\n---\n\n")[1]
        imp = en.split("## Bumps in security-sensitive packages")[1].split("\n## ")[0]
        self.assertIn("`nss`", imp)
        self.assertNotIn("`nspr`", imp)

        old = {"foo-a": pkg("foo-a", "1.0-1.fc45", src="foo"),
               "foo-b": pkg("foo-b", "2.0-1.fc45", src="foo")}
        new = {"foo-a": pkg("foo-a", "2.0-1.fc45", src="foo"),
               "foo-b": pkg("foo-b", "1.0-1.fc45", src="foo")}
        diff = S.pkg_diff(old, new)
        for ch in diff["changed"]:
            ch["cls"] = S.classify_change(ch["old"], ch["new"], "F45", None)
        layers = S.layer_diff({"layers": []}, {"layers": []})
        verdict = S.verdict_of(diff, layers, {})
        image = {"ref": "test", "digest": "sha256:" + "a" * 64, "annotations": {}}
        en_routine = S.render_markdown("m", image, image, diff, layers, verdict, []).split("\n\n---\n\n")[1]
        sec = en_routine.split("## Routine bumps (1 source package(s), 1 binary)")[1].split("\n## ")[0]
        self.assertIn("`foo-a`", sec)
        self.assertNotIn("`foo-b`", sec)
