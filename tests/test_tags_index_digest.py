"""`tags` names the watched image by the digest its dated tags are compared with."""
import contextlib
import io
import unittest
from unittest.mock import patch

from test_sbwatch import S

IDX, PLAT = "sha256:" + "a" * 64, "sha256:" + "b" * 64
CUR = {"digest": PLAT, "index_digest": IDX, "created": "2026-01-02T00:00:00Z",
       "layers": [], "annotations": {}}


class TestTagsIndexDigest(unittest.TestCase):
    def test_index_digest_first_then_the_platform_one(self):
        out = io.StringIO()
        with patch.object(S.Registry, "_token", return_value=None), \
                patch.object(S, "resolve",
                             side_effect=lambda reg, ref, light=False: dict(CUR, ref=ref)), \
                patch.object(S, "tag_exists", side_effect=lambda reg, tag, warn=None: IDX), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(S.main(["tags", "--image", "x/y", "--days", "1"]), 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], f"latest -> {IDX}")
        self.assertTrue(lines[1].endswith(PLAT))
        self.assertTrue(any(IDX in line and line.endswith("== latest") for line in lines[2:]))


if __name__ == "__main__":
    unittest.main()
