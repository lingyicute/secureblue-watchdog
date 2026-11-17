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

    def test_branch_preview_tag_is_excluded_when_watching_latest(self):
        cur, live_prev, br_next = _image(3), _image(1), _image(2)
        images = {i["digest"]: i for i in (cur, live_prev, br_next)}
        tags = ["br-next-45",
                "sha256-" + live_prev["digest"][7:] + ".sig",
                "sha256-" + br_next["digest"][7:] + ".sig"]

        class _Reg:
            def index_digest(self, ref):
                return br_next["digest"]

        with patch.object(S, "list_tags", return_value=tags),                 patch.object(S, "resolve",
                             side_effect=lambda reg, ref, light=False: dict(images[ref], ref=ref)):
            rows = S.build_history(_Reg(), scan=5, days=0, to="latest", cur=cur)
        self.assertEqual([r["digest"] for r in rows], [cur["digest"], live_prev["digest"]])


    def test_pr_preview_and_sibling_branch_tags_are_excluded(self):
        cur, pr_img, other_br, same_br = _image(4), _image(3), _image(2), _image(1)
        images = {i["digest"]: i for i in (cur, pr_img, other_br, same_br)}
        by_tag = {"pr-99-45": pr_img["digest"], "br-staging-45": other_br["digest"],
                  "br-next-45": cur["digest"]}
        tags = [*by_tag, *("sha256-" + i["digest"][7:] + ".sig"
                           for i in (same_br, other_br, pr_img, cur))]

        class _Reg:
            def index_digest(self, ref):
                return by_tag[ref]

        with patch.object(S, "list_tags", return_value=tags), \
                patch.object(S, "resolve",
                             side_effect=lambda reg, ref, light=False: dict(images[ref], ref=ref)):
            rows = S.build_history(_Reg(), scan=5, days=0, to="br-next-45", cur=cur)
        self.assertEqual([r["digest"] for r in rows], [cur["digest"], same_br["digest"]])


if __name__ == "__main__":
    unittest.main()
