"""A no-change verdict must name every changed chunk of unowned files, not only
chunkah/unclaimed: secureblue's own configuration also ships as bigfiles/*."""
import unittest

from test_sbwatch import S


def chunk(component, size):
    return {"components": [component], "size": size, "stability": 0.0}


def verdict(*chunks):
    diff = S.pkg_diff({}, {})
    ldiff = {"download_bytes": sum(c["size"] for c in chunks), "changed_chunks": list(chunks)}
    return S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff))


class TestUnownedBigfilesNote(unittest.TestCase):
    def test_secureblue_config_in_a_bigfiles_chunk_is_disclosed(self):
        # component and size as in the live 45.20261117.0 manifest
        v = verdict(chunk("bigfiles/usr/share/secureblue/etc/trivalent/filter/"
                          "trivalent-blocklist", 4931496))
        self.assertEqual(v["level"], "no-change")
        self.assertIn("Not inspected: 4.7 MiB", v["headline"])
        self.assertIn("未检查", v["headline_zh"])

    def test_the_rpmdb_chunk_alone_is_not_unowned_content(self):
        v = verdict(chunk("bigfiles/rpmdb.sqlite", 33504432))
        self.assertEqual(v["level"], "no-change")
        self.assertNotIn("Not inspected", v["headline"])

    def test_a_regenerated_initramfs_alone_adds_nothing(self):
        v = verdict(chunk("bigfiles/initramfs.img", 247026065))
        self.assertNotIn("Not inspected", v["headline"])

    def test_unclaimed_still_counts(self):
        v = verdict(chunk("chunkah/unclaimed", 9962319))
        self.assertIn("Not inspected: 9.5 MiB", v["headline"])

    def test_markdown_no_change_section_matches_headline_for_bigfiles(self):
        ch = chunk("bigfiles/usr/share/secureblue/etc/trivalent/filter/trivalent-blocklist", 4931496)
        diff = S.pkg_diff({}, {})
        ldiff = {"chunks_a": 1, "chunks_b": 1, "chunks_changed": 1, "chunks_reused": 0,
                 "total_size_b": ch["size"], "download_bytes": ch["size"], "download_pct": 100,
                 "changed_packages_from_chunks": [], "changed_chunks": [ch]}
        v = S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff))
        img = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        md = S.render_markdown("s", img, img, diff, ldiff, v, [])
        self.assertIn("4.7 MiB in changed compressed layers containing unowned", md)
        self.assertIn("含无归属组件的变化压缩层共 4.7 MiB", md)

    def test_mixed_chunk_total_is_for_compressed_blobs_not_changed_files(self):
        # Two of the four chunks the live 45.20261123.0 moved without a package change:
        # chunkah packs unowned files (SELinux policy, hwdb.bin) next to rpm/ components.
        shared = {"components": ["bigfiles/policy.kern",
                                 "bigfiles/usr/share/secureblue/etc/selinux/targeted/active/policy.linked",
                                 "rpm/PackageKit", "rpm/SDL3", "rpm/at-spi2-core"],
                  "size": 56197659, "stability": 0.0}
        own = chunk("chunkah/unclaimed", 9970218)
        v = verdict(shared, own)
        self.assertEqual(v["level"], "no-change")
        self.assertIn("Not inspected: 63.1 MiB in changed compressed layers", v["headline"])
        self.assertIn("1 of these layers also carry other components", v["headline"])
        self.assertIn("未检查：含无归属组件的变化压缩层共 63.1 MiB", v["headline_zh"])
        self.assertIn("其中 1 层还含有其他组件", v["headline_zh"])
        diff = S.pkg_diff({}, {})
        ldiff = {"chunks_a": 2, "chunks_b": 2, "chunks_changed": 2, "chunks_reused": 0,
                 "total_size_b": 66167877, "download_bytes": 66167877, "download_pct": 100,
                 "changed_packages_from_chunks": [], "changed_chunks": [shared, own]}
        img = {"ref": "a", "digest": "sha256:" + "a" * 64, "annotations": {}, "layers": []}
        md = S.render_markdown("s", img, img, diff, ldiff,
                               S.verdict_of(diff, ldiff, {}, S.crosscheck_chunks(ldiff, diff)), [])
        self.assertIn("63.1 MiB in changed compressed layers", md)
        self.assertIn("This is not a measure of changed files.", md)
        self.assertIn("含无归属组件的变化压缩层共 63.1 MiB", md)
        self.assertIn("这不是文件变化量。", md)

    def test_empty_component_annotation_counts_as_unowned(self):
        import io
        import json

        class _Resp(io.BytesIO):
            headers = {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}

        reg = S.Registry("ghcr.io/x/y")
        body = json.dumps({"layers": [{
            "digest": "sha256:" + "a" * 64, "size": 2048,
            "annotations": {"org.chunkah.component": "   "},
        }]}).encode()
        reg._open = lambda path, accept: _Resp(body)
        resolved = reg.resolve("latest", light=True)
        self.assertEqual(resolved["layers"][0]["components"], ["chunkah/unclaimed"])
        empty_chunk = {"components": [], "size": 2048, "stability": 0.0}
        self.assertEqual(S._unowned_chunk_bytes({"changed_chunks": [empty_chunk]}), (2048, 0))


if __name__ == "__main__":
    unittest.main()
