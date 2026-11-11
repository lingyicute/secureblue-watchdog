"""A 200 that is no manifest is a registry error with a message, not a traceback."""
import io
import json
import unittest

from test_sbwatch import S


class _Resp(io.BytesIO):
    headers = {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}


def _registry(body):
    reg = S.Registry("ghcr.io/x/y")
    reg._open = lambda path, accept: _Resp(body)
    return reg


def _layer(**extra):
    return dict({"digest": "sha256:" + "a" * 64,
                 "annotations": {"org.chunkah.component": "rpm/curl"}}, **extra)


class TestMalformedManifest(unittest.TestCase):
    def _refused(self, body):
        with self.assertRaises(S.MalformedManifest) as ctx:
            _registry(body).resolve("latest", light=True)
        self.assertIsInstance(ctx.exception, S.RegistryError)
        self.assertIn("x/y:latest is not a readable image manifest", str(ctx.exception.code))
        return str(ctx.exception.code)

    def test_a_body_that_is_not_json(self):
        self.assertIn("JSONDecodeError", self._refused(b"<html>502 Bad Gateway</html>"))

    def test_json_that_is_not_an_object(self):
        self._refused(b"[]")

    def test_a_layer_without_a_size(self):
        self.assertIn("KeyError", self._refused(json.dumps({"layers": [_layer()]}).encode()))

    def test_a_layer_that_is_not_an_object(self):
        self._refused(json.dumps({"layers": ["sha256:" + "a" * 64]}).encode())

    def test_a_stability_that_is_not_a_number(self):
        bad = _layer(size=5)
        bad["annotations"]["org.chunkah.stability"] = "high"
        self._refused(json.dumps({"layers": [bad]}).encode())

    def test_a_well_formed_manifest_still_resolves(self):
        out = _registry(json.dumps({"layers": [_layer(size=5)]}).encode()).resolve(
            "latest", light=True)
        self.assertEqual([(l["size"], l["components"]) for l in out["layers"]],
                         [(5, ["rpm/curl"])])


class TestHistoryNamesTheCause(unittest.TestCase):
    def test_a_malformed_build_is_not_reported_as_a_network_error(self):
        cur = {"index_digest": "sha256:" + "c" * 64, "digest": "sha256:" + "d" * 64,
               "created": "2026-11-11T00:00:00Z", "annotations": {}, "layers": []}

        def broken(reg, ref, light=False):
            raise S.MalformedManifest("not a manifest")

        saved = S.list_tags, S.resolve
        S.list_tags = lambda reg, max_pages=12: ["sha256-" + "b" * 64 + ".sig"]
        S.resolve = broken
        try:
            warn: list = []
            rows = S.build_history(S.Registry("ghcr.io/x/y"), days=0, warn=warn, cur=cur)
        finally:
            S.list_tags, S.resolve = saved
        self.assertEqual(len(rows), 1)
        self.assertIn("(malformed manifest)", warn[0])
        self.assertNotIn("network error", warn[0])


if __name__ == "__main__":
    unittest.main()
