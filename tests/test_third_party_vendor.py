"""Third-party vendor RPMs must not match Fedora Bodhi errata as Fedora builds."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from test_sbwatch import S, pkg, rpm_header


class _Bodhi:
    def __init__(self, updates):
        self.updates = updates
        self.queried = []

    def updates_for_src(self, src, release):
        self.queried.append((src, release))
        return list(self.updates)


class TestThirdPartyVendor(unittest.TestCase):
    def test_negativo17_nvr_collision_does_not_claim_fedora_erratum_or_query_bodhi(self):
        # Live F45 image ships negativo17 ffmpeg 1:9.0.2-2.fc45; Bodhi's
        # FEDORA-2026-91259c13b9 lists Fedora's epoch-0 ffmpeg-9.0.2-2.fc45.
        old = dict(pkg("ffmpeg", "9.0.2-1.fc45", epoch="1"), vendor="negativo17.org")
        new = dict(pkg("ffmpeg", "9.0.2-2.fc45", epoch="1"), vendor="negativo17.org")
        bodhi = _Bodhi([{"alias": "FEDORA-2026-91259c13b9", "type": "security",
                         "severity": "high", "status": "stable", "title": "",
                         "notes": "", "cves": ["CVE-2026-84975"], "bugs": [],
                         "date_approved": None, "nvrs": ["ffmpeg-9.0.2-2.fc45"]}])
        cls = S.classify_change(old, new, "F45", bodhi)
        self.assertEqual(bodhi.queried, [])
        self.assertFalse(cls["security"])
        self.assertFalse(cls["has_security_erratum"])
        self.assertEqual(cls["cves"], [])
        self.assertEqual(cls["aliases"], [])

    def test_fedora_project_vendor_still_attaches_erratum(self):
        old = dict(pkg("dnf5", "5.4.7.0-1.fc45"), vendor="Fedora Project")
        new = dict(pkg("dnf5", "5.4.8.0-2.fc45"), vendor="Fedora Project")
        bodhi = _Bodhi([{"alias": "FEDORA-2026-b9a53ff63c", "type": "security",
                         "severity": "high", "status": "stable", "title": "",
                         "notes": "", "cves": ["CVE-2026-123177"], "bugs": [],
                         "date_approved": None, "nvrs": ["dnf5-5.4.8.0-2.fc45"]}])
        cls = S.classify_change(old, new, "F45", bodhi)
        self.assertTrue(cls["has_security_erratum"])
        self.assertEqual(cls["cves"], ["CVE-2026-123177"])

    def test_empty_vendor_secureblue_kernel_rebuild_still_matches_normalised(self):
        old = dict(pkg("kernel", "7.3.2-300.secureblue.1.fc45"), vendor="")
        new = dict(pkg("kernel", "7.3.3-300.secureblue.2.fc45"), vendor="")
        bodhi = _Bodhi([{"alias": "FEDORA-2026-655049a906", "type": "security",
                         "severity": "medium", "status": "stable", "title": "",
                         "notes": "", "cves": [], "bugs": [],
                         "date_approved": None, "nvrs": ["kernel-7.3.3-300.fc45"]}])
        cls = S.classify_change(old, new, "F45", bodhi)
        self.assertTrue(cls["advisory_corresponding"])
        self.assertFalse(cls["has_security_erratum"])

    def test_third_party_secureblue_rebuild_matches_only_as_corresponding(self):
        old = dict(pkg("foo", "1.0-1.secureblue.1.fc45"), vendor="Fedora Copr - user secureblue")
        new = dict(pkg("foo", "1.1-1.secureblue.1.fc45"), vendor="Fedora Copr - user secureblue")
        bodhi = _Bodhi([{"alias": "FEDORA-2026-foo", "type": "security",
                         "severity": "high", "status": "stable", "title": "",
                         "notes": "", "cves": ["CVE-2026-1234"], "bugs": [],
                         "date_approved": None,
                         "nvrs": ["foo-1.1-1.fc45", "foo-1.0-2.fc45"]}])
        cls = S.classify_change(old, new, "F45", bodhi)
        self.assertTrue(cls["advisory_corresponding"])
        self.assertFalse(cls["has_security_erratum"])
        self.assertEqual(cls["passed_over"], [])

    def test_package_list_preserves_vendor_tag(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "rpmdb.sqlite"
            con = sqlite3.connect(db)
            con.execute("create table Packages (blob BLOB)")
            blob = rpm_header([(1000, 6, b"ffmpeg\0"), (1001, 6, b"9.0.2\0"),
                               (1002, 6, b"2.fc45\0"), (1011, 6, b"negativo17.org\0"),
                               (1044, 6, b"ffmpeg-9.0.2-2.fc45.src.rpm\0")])
            con.execute("insert into Packages values (?)", (blob,))
            con.commit()
            con.close()

            class _Reg:
                def extract_member(self, layer, match):
                    return str(db)

            img = {"layers": [{"digest": "sha256:" + "a" * 64, "size": 1,
                               "components": ["bigfiles/rpmdb.sqlite"]}]}
            table = S.package_list(_Reg(), img)
            self.assertEqual(table["ffmpeg"]["vendor"], "negativo17.org")


    def test_copr_secureblue_kernel_rebuild_catches_passed_over_fedora_erratum(self):
        old = dict(pkg("kernel", "7.2.15-300.secureblue.1.fc45"),
                   vendor="Fedora Copr - user secureblue")
        new = dict(pkg("kernel", "7.3.4-300.secureblue.1.fc45"),
                   vendor="Fedora Copr - user secureblue")
        bodhi = _Bodhi([{"alias": "FEDORA-2026-655049a906", "type": "security",
                         "severity": "medium", "status": "stable", "title": "",
                         "notes": "", "cves": ["CVE-2026-4242"], "bugs": [],
                         "date_approved": None, "nvrs": ["kernel-7.3.3-300.fc45"]}])
        cls = S.classify_change(old, new, "F45", bodhi)
        self.assertTrue(cls["security"])
        self.assertFalse(cls["has_security_erratum"])
        self.assertEqual([x["alias"] for x in cls["passed_over"]], ["FEDORA-2026-655049a906"])
        self.assertEqual(cls["cves"], ["CVE-2026-4242"])


if __name__ == "__main__":
    unittest.main()
