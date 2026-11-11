"""Indexes without the rpmdb chunk are no builds of a chunked image."""
import unittest
from unittest.mock import patch

from test_sbwatch import S


def _image(n, chunked=True):
    digest = "sha256:" + str(n) * 64
    component = "bigfiles/rpmdb.sqlite" if chunked else "chunkah/unclaimed"
    return {"digest": digest, "index_digest": digest, "is_index": True,
            "created": f"2026-01-0{n}T00:00:00Z", "annotations": {},
            "layers": [{"digest": f"sha256:layer{n}", "size": 1, "stability": 0.0,
                        "components": [component]}]}


def _history(cur, *others):
    images = {i["digest"]: i for i in (cur, *others)}
    tags = ["sha256-" + i["digest"][7:] + ".sig" for i in others]
    with patch.object(S, "list_tags", return_value=tags), \
            patch.object(S, "resolve",
                         side_effect=lambda reg, ref, light=False: dict(images[ref], ref=ref)):
        rows = S.build_history(None, scan=5, days=0, to="latest", cur=cur)
    return [r["digest"] for r in rows]


class TestHistoryForeignBuilds(unittest.TestCase):
    def test_unchunked_index_is_left_out_of_a_chunked_images_history(self):
        cur, proper, derived = _image(3), _image(1), _image(2, chunked=False)
        self.assertEqual(_history(cur, proper, derived), [cur["digest"], proper["digest"]])

    def test_it_does_not_use_up_the_scan_limit(self):
        cur = _image(9)
        derived = [_image(n, chunked=False) for n in (5, 6, 7, 8)]
        proper = [_image(n) for n in (1, 2, 3, 4)]
        self.assertEqual(_history(cur, *proper, *derived),
                         [i["digest"] for i in (cur, *reversed(proper))])

    def test_an_image_without_the_chunk_layout_keeps_its_whole_history(self):
        cur, older = _image(3, chunked=False), _image(2, chunked=False)
        self.assertEqual(_history(cur, older), [cur["digest"], older["digest"]])


if __name__ == "__main__":
    unittest.main()
