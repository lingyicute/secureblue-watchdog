#!/usr/bin/env python3
"""
sbwatch - know what a secureblue (or any chunkah/rpm-ostree OCI image) update
actually changes, *before* you download it.

Why this works without pulling the image
----------------------------------------
secureblue images are built with blue-build + `chunkah` rechunking, so every OCI
layer is annotated with the RPM packages it carries:

    "annotations": {
      "org.chunkah.component": "rpm/kernel rpm/curl",
      "org.chunkah.stability": "0.006"
    }

Two things fall out of that for free:

 1. The manifest (~50 KB) is a package -> chunk map. Comparing two manifests
    tells you which packages' content changed and which chunks have to be
    re-downloaded (=> the real update size).
 2. The whole RPM database ships as its own chunk (`bigfiles/rpmdb.sqlite`), so
    fetching that *single* blob (~33 MB instead of ~4 GB) gives the exact NEVRA
    of all ~2200 packages plus their changelogs (where Fedora writes
    "Fix CVE-YYYY-NNNNN"). That yields a precise per-package version diff.

Everything here is stdlib-only (urllib + sqlite3): no podman, no root, no
registry login (the anonymous ghcr pull token is enough).

CLI
---
  sbwatch tags                  recent dated tags of an image / 近期按日期的标签
  sbwatch history               every recent build (several per day included) / 近期全部构建（含一天多次）
  sbwatch layers A B            chunk-level diff + predicted download size / chunk 级差异 + 预计下载量
  sbwatch pkgs A                exact package list (NEVRA) of one image / 单个镜像的精确软件包列表（NEVRA）
  sbwatch diff A B              exact package diff + CVE classification / 精确软件包差异 + CVE 分类
  sbwatch backlog [ref]         security updates this image is still missing / 此镜像仍缺少的安全更新
  sbwatch check                 stateful digest watch for CI/cron / 有状态 digest 监控（用于 CI/cron）
                                -> report.md + verdict + $GITHUB_OUTPUT

  All human-readable output is bilingual: English + 中文（所有输出均为中英双语）
  A / B / ref  = latest | 44 | 20260915 | 9ec80ca-44 | sha256:<digest>
  (digests are the only immutable way to name one specific build / digest 是命名某次构建的唯一不可变方式)
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# make bilingual (CJK) output safe even under a C/POSIX locale
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

DEFAULT_IMAGE = "secureblue/silverblue-main-hardened"
# P0 hardening limits (anti zip-bomb / DoS)
MAX_BLOB_BYTES = 200 * 1024 * 1024          # 200 MiB compressed
MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MiB decompressed
MAX_TAR_MEMBERS = 10_000
MAX_TAR_FILE_SIZE = 100 * 1024 * 1024       # 100 MiB single file inside tar
MANIFEST_ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SEC_WORDS_RE = re.compile(
    r"(security fix|fix(es)? .{0,40}vulnerab|buffer overflow|use-after-free|"
    r"privilege escalation|out.of.bounds)", re.I)

# source packages whose movement deserves attention even without an obvious CVE
IMPORTANT_SRC = {
    "kernel", "glibc", "openssl", "nss", "systemd", "sudo", "polkit", "rpm-ostree",
    "ostree", "container-selinux", "selinux-policy", "libcap", "pam", "shadow-utils",
    "openssh", "curl", "dnf", "rpm", "grub2", "shim", "mutter", "gnome-shell",
    "gupnp", "webkitgtk", "firefox", "thunderbird", "trivalent",
    "trivalent-native", "trivalent-binary-packaging", "flatpak", "xdg-desktop-portal",
    "pipewire", "xorg-x11-server", "linux-firmware", "crun", "runc", "usbguard",
    "bubblewrap", "fwupd", "bluez", "cups", "avahi", "libarchive", "expat", "gnutls",
}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def T(en: str, zh: str) -> str:
    """Bilingual user-facing message: English first, then Chinese（中英双语输出）."""
    return f"{en} / {zh}"


def human(nbytes) -> str:
    n = float(nbytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TiB"


def _safe_read_limited(resp, limit: int) -> bytes:
    """Read from HTTPResponse with hard limit to avoid OOM / zip-bomb."""
    cl = resp.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > limit:
        raise SystemExit(T(f"blob Content-Length {cl} > {human(limit)} limit - aborting",
                           f"blob Content-Length {cl} 超过 {human(limit)} 限制——中止"))
    chunks = []
    total = 0
    while True:
        chunk = resp.read(1 << 20)  # 1 MiB
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise SystemExit(T(f"blob exceeds {human(limit)} limit during download - possible bomb",
                               f"下载过程中 blob 超过 {human(limit)} 限制——疑似 zip 炸弹"))
        chunks.append(chunk)
    return b"".join(chunks)


def verify_cosign_image(full_ref: str, pubkey_path: str, require: bool = False) -> bool:
    """
    P0: optional cosign signature verification.
    full_ref = host/repo@sha256:digest or host/repo:tag
    Returns True if verified, False if skipped/failed (and not required).
    Raises SystemExit if require=True and verification fails.
    """
    if not pubkey_path:
        return False
    if not os.path.exists(pubkey_path):
        msg = T(f"cosign pubkey not found: {pubkey_path}",
                f"找不到 cosign 公钥：{pubkey_path}")
        if require:
            raise SystemExit(msg)
        log(f"  ! {msg} - skipping verification / 跳过校验")
        return False
    cosign_bin = shutil.which("cosign")
    if not cosign_bin:
        msg = T("cosign binary not found in PATH - install sigstore/cosign to enable verification",
                "PATH 中找不到 cosign 可执行文件——请安装 sigstore/cosign 以启用校验")
        if require:
            raise SystemExit(msg)
        log(f"  ! {msg} - skipping / 跳过")
        return False
    # secureblue publishes cosign.pub at https://github.com/secureblue/secureblue/blob/live/cosign.pub
    cmd = [cosign_bin, "verify", "--key", pubkey_path, full_ref]
    log(T(f"  verifying {full_ref} with cosign...",
          f"  正在使用 cosign 校验 {full_ref}…"))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if res.returncode == 0:
            log(T(f"  cosign verify OK for {full_ref}",
                  f"  cosign 校验成功：{full_ref}"))
            return True
        else:
            err = (res.stderr or res.stdout)[:500]
            msg = T(f"cosign verify FAILED for {full_ref}: {err}",
                    f"cosign 校验失败：{full_ref}：{err}")
            if require:
                raise SystemExit(msg)
            log(f"  ! {msg}")
            return False
    except subprocess.TimeoutExpired:
        msg = T(f"cosign verify timeout for {full_ref}",
                f"cosign 校验超时：{full_ref}")
        if require:
            raise SystemExit(msg)
        log(f"  ! {msg}")
        return False
    except Exception as e:
        msg = T(f"cosign verify error: {e}",
                f"cosign 校验出错：{e}")
        if require:
            raise SystemExit(msg)
        log(f"  ! {msg}")
        return False


def maybe_verify_resolved(reg: Registry, resolved: dict, args) -> None:
    """If --cosign-pub is set, verify the resolved digest."""
    pub = getattr(args, "cosign_pub", None)
    if not pub:
        return
    req = getattr(args, "require_cosign", False)
    # build full ref: host/repo@digest (digest is the image digest, not index digest if possible)
    digest = resolved.get("digest") or resolved.get("index_digest")
    if not digest:
        log(T("  ! cannot verify: no digest in resolved image",
              "  ！无法校验：解析到的镜像中没有 digest"))
        if req:
            raise SystemExit(T("no digest for cosign verification",
                           "没有可用于 cosign 校验的 digest"))
        return
    full_ref = f"{reg.host}/{reg.repo}@{digest}"
    verify_cosign_image(full_ref, pub, require=req)


# --------------------------------------------------------------------------- #
# rpm version comparison
# --------------------------------------------------------------------------- #
def _ver_split(s: str) -> list:
    """Split a version into rpm's comparison segments: digit runs, alpha runs, '~'."""
    out, i, n = [], 0, len(s or "")
    while i < n:
        c = s[i]
        if c == "~":
            out.append("~")
            i += 1
        elif c.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            out.append(s[i:j])
            i = j
        elif c.isalpha():
            j = i
            while j < n and s[j].isalpha():
                j += 1
            out.append(s[i:j])
            i = j
        else:
            i += 1                     # separators (. - + :) are ignored
    return out


def rpmvercmp(a: str, b: str) -> int:
    """RPM's rpmvercmp: numeric segments compare numerically, '~' sorts before anything."""
    la, lb = _ver_split(a), _ver_split(b)
    i = 0
    while i < len(la) or i < len(lb):
        if i >= len(la):
            return 1 if lb[i] == "~" else -1
        if i >= len(lb):
            return -1 if la[i] == "~" else 1
        x, y = la[i], lb[i]
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
        elif x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif x != y:
            return -1 if x < y else 1
        i += 1
    return 0


def evr_cmp(a: dict, b: dict) -> int:
    return (rpmvercmp(a.get("epoch") or "0", b.get("epoch") or "0")
            or rpmvercmp(a.get("version", ""), b.get("version", ""))
            or rpmvercmp(a.get("release", ""), b.get("release", "")))


# --------------------------------------------------------------------------- #
# OCI registry client (anonymous, stdlib only)
# --------------------------------------------------------------------------- #
class Registry:
    def __init__(self, ref: str, arch: str = "amd64", timeout: int = 90):
        self.arch = arch
        self.timeout = timeout
        self.host, (self.repo, self.default_ref) = self._split(ref)
        self._tok: str | None = None
        self._tmp = tempfile.mkdtemp(prefix="sbwatch-")

    @staticmethod
    def _split(ref: str):
        ref = (ref or "").removeprefix("docker://").strip().removeprefix("oci:")
        if ref.count("/") < 1:
            raise SystemExit(T(f"need a reference like host/ns/name:tag, got: {ref}",
                               f"需要形如 host/ns/name:tag 的引用，实际收到：{ref}"))
        first, _, rest_all = ref.partition("/")
        if "." not in first and ":" not in first and first != "localhost":
            host, rest = "ghcr.io", ref          # bare ns/name -> ghcr.io (secureblue's home)
        else:
            host, rest = first, rest_all
        if "@" in rest:
            repo, _, dig = rest.partition("@")
        elif ":" in rest.rsplit("/", 1)[-1]:
            repo, _, tag = rest.rpartition(":")
            dig = tag
        else:
            repo, dig = rest, "latest"
        return host, (repo, dig)

    def _token(self):
        if self._tok is not None:
            return self._tok or None
        tok = None
        try:
            req = urllib.request.Request(f"https://{self.host}/v2/")
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except urllib.error.HTTPError as e:
            h = e.headers.get("Www-Authenticate") or ""
            m = re.match(r"Bearer\s+(.*)", h, re.S)
            if m:
                parts = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
                realm = parts.get("realm")
                q = {"service": parts.get("service", ""),
                     "scope": f"repository:{self.repo}:pull"}
                url = realm + "?" + urllib.parse.urlencode({k: v for k, v in q.items() if v})
                try:
                    with urllib.request.urlopen(url, timeout=self.timeout) as r:
                        tok = json.load(r).get("token", "")
                except Exception as e2:
                    log(T(f"  ! token fetch failed: {e2}",
                          f"  ！获取 token 失败：{e2}"))
        self._tok = tok or ""
        return tok or None

    def _open(self, path: str, accept: str):
        url = f"https://{self.host}/v2/{self.repo}/{path.lstrip('/')}"
        req = urllib.request.Request(url, headers={"Accept": accept})
        tok = self._token()
        if tok:
            req.add_header("Authorization", "Bearer " + tok)
        return urllib.request.urlopen(req, timeout=self.timeout)

    def get(self, path: str, accept: str) -> bytes:
        with self._open(path, accept) as r:
            # manifest is small, blobs can be large - enforce same limit for safety
            return _safe_read_limited(r, MAX_BLOB_BYTES)

    def resolve(self, ref: str | None = None, light: bool = False) -> dict:
        """manifest + config for one architecture, plus a normalized chunk list."""
        what = ref or self.default_ref
        with self._open(f"manifests/{what}", MANIFEST_ACCEPT) as r:
            raw = r.read()
            top_digest = r.headers.get("Docker-Content-Digest") or ""
            ctype = r.headers.get("Content-Type", "")
        if not top_digest:
            top_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        man = json.loads(raw)
        out = {"ref": what, "index_digest": top_digest, "mediaType": ctype,
               "is_index": "index" in ctype or "manifests" in man}
        if "index" in ctype or "manifests" in man:
            pick = None
            for m in man.get("manifests", []):
                p = m.get("platform") or {}
                if p.get("architecture") == self.arch and p.get("os", "linux") == "linux":
                    pick = m
                    break
            if pick is None:
                raise SystemExit(T(f"no {self.arch} manifest in {self.repo}:{what}",
                                   f"{self.repo}:{what} 中没有 {self.arch} 架构的 manifest"))
            man = json.loads(self.get(f"manifests/{pick['digest']}", MANIFEST_ACCEPT))
            out["digest"] = pick["digest"]
        else:
            out["digest"] = top_digest
        out["manifest"] = man
        ann = dict(man.get("annotations") or {})
        cfg = {}
        if not light:
            cfg = json.loads(self.get(f"blobs/{man['config']['digest']}",
                                      "application/vnd.oci.image.config.v1+json"))
            ann.update(dict((cfg.get("config") or {}).get("Labels") or {}))
        out["config"] = cfg
        out["annotations"] = ann
        out["created"] = (cfg.get("created") or ann.get("org.opencontainers.image.created")
                          or "")[:20]
        out["layers"] = []
        for l in man.get("layers", []):
            la = l.get("annotations") or {}
            out["layers"].append({
                "digest": l["digest"],
                "size": int(l["size"]),
                "components": la.get("org.chunkah.component", "chunkah/unclaimed").split(),
                "stability": float(la.get("org.chunkah.stability", 0) or 0),
            })
        return out

    def extract_member(self, layer: dict, match: str) -> str:
        """Download one layer blob, return a local path to the file inside it named *match*."""
        data = self.get(f"blobs/{layer['digest']}", "application/octet-stream")
        # --- safe decompress with size cap ---
        if data[:2] == b"\x1f\x8b":
            out_buf = io.BytesIO()
            total = 0
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    while True:
                        chunk = gz.read(1 << 20)  # 1 MiB
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_DECOMPRESSED_BYTES:
                            raise SystemExit(T(
                                f"decompressed layer > {human(MAX_DECOMPRESSED_BYTES)} "
                                f"limit - possible zip bomb (layer {layer['digest'][:19]})",
                                f"层解压后超过 {human(MAX_DECOMPRESSED_BYTES)} 限制——"
                                f"疑似 zip 炸弹（层 {layer['digest'][:19]}）"))
                        out_buf.write(chunk)
            except (OSError, gzip.BadGzipFile, EOFError) as e:
                raise SystemExit(T(f"gzip decompress failed for {layer['digest'][:19]}: {e}",
                                   f"gzip 解压失败：{layer['digest'][:19]}：{e}"))
            data = out_buf.getvalue()
        else:
            if len(data) > MAX_DECOMPRESSED_BYTES:
                raise SystemExit(T(
                    f"uncompressed layer > {human(MAX_DECOMPRESSED_BYTES)} limit "
                    f"(layer {layer['digest'][:19]})",
                    f"未压缩层超过 {human(MAX_DECOMPRESSED_BYTES)} 限制"
                    f"（层 {layer['digest'][:19]}）"))
        dest = os.path.join(self._tmp, re.sub(r"\W+", "_", match) + ".extracted")
        # --- tar hardening ---
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            members = tf.getmembers()
            if len(members) > MAX_TAR_MEMBERS:
                raise SystemExit(T(
                    f"tar has {len(members)} members > {MAX_TAR_MEMBERS} limit "
                    f"(layer {layer['digest'][:19]})",
                    f"tar 包含 {len(members)} 个成员，超过 {MAX_TAR_MEMBERS} 限制"
                    f"（层 {layer['digest'][:19]}）"))
            by_name = {m.name.lstrip("./"): m for m in members}
            chosen = None
            for m in members:
                nm = m.name.lstrip("./")
                if match in nm and m.isfile():
                    chosen = m
                    break
                if match in nm and m.issym():
                    tgt = m.linkname.lstrip("./")
                    if tgt in by_name and by_name[tgt].isfile():
                        chosen = by_name[tgt]
                        break
            if chosen is None:
                raise SystemExit(T(f"'{match}' not found in layer {layer['digest'][:19]}",
                                   f"在层 {layer['digest'][:19]} 中找不到 '{match}'"))
            if chosen.size > MAX_TAR_FILE_SIZE:
                raise SystemExit(T(
                    f"tar member {chosen.name} size {human(chosen.size)} > "
                    f"{human(MAX_TAR_FILE_SIZE)} limit",
                    f"tar 成员 {chosen.name} 大小 {human(chosen.size)} 超过 "
                    f"{human(MAX_TAR_FILE_SIZE)} 限制"))
            f = tf.extractfile(chosen)
            if f is None:
                raise SystemExit(T("unreachable member", "无法读取的 tar 成员"))
            # stream out with size check
            total_written = 0
            with open(dest, "wb") as o:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > MAX_TAR_FILE_SIZE:
                        raise SystemExit(T(f"extracted file > {human(MAX_TAR_FILE_SIZE)} limit",
                                           f"解出的文件超过 {human(MAX_TAR_FILE_SIZE)} 限制"))
                    o.write(chunk)
        del data
        return dest

# --------------------------------------------------------------------------- #
# reading the RPM database out of the `bigfiles/rpmdb.sqlite` chunk
# --------------------------------------------------------------------------- #
RPMTAG = {
    1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1004: "summary",
    1005: "description", 1006: "buildhost", 1007: "buildhost", 1010: "vendor",
    1011: "license", 1022: "arch", 1044: "sourcerpm", 1080: "changelogtime",
    1081: "changelogname", 1082: "changelogtext",
}
STR_TYPES = {6, 8, 9}   # 6=STRING, 8=STRING_ARRAY, 9=I18NSTRING
INT_TAGS = {"changelogtime", "epoch", "size"}
CHUNK_MATCH = "rpmdb.sqlite"


def read_header(blob: bytes) -> dict:
    """Parse the rpm header stored in the sqlite/ndb `Packages` table."""
    if blob[:3] == b"\x8e\xad\xe8":          # legacy header w/ magic + reserved
        if len(blob) < 20:
            return {}
        nindex, hlen = struct.unpack(">II", blob[12:20])
        base = 20
    else:                                    # rpm>=4.16 ndb blob: nindex, hlen, ...
        if len(blob) < 8:
            return {}
        nindex, hlen = struct.unpack(">II", blob[:8])
        base = 8
    if 8 + 16 * nindex + hlen > len(blob) + 40:
        return {}
    store = base + 16 * nindex
    out: dict = {}
    for i in range(nindex):
        tag, typ, off, cnt = struct.unpack(">IIII", blob[base + 16 * i: base + 16 * i + 16])
        name = RPMTAG.get(tag)
        if not name or name in out:
            continue
        p = store + off
        try:
            if name == "changelogtime":
                out[name] = list(struct.unpack(">%dI" % cnt, blob[p:p + 4 * cnt]))
                continue
            if name == "epoch":
                out[name] = str(struct.unpack(">I", blob[p:p + 4])[0])
                continue
            if typ in STR_TYPES:
                if cnt > 1:                              # array of strings
                    arr, q = [], p
                    for _ in range(cnt):
                        e = blob.index(b"\0", q)
                        arr.append(blob[q:e].decode("utf-8", "replace"))
                        q = e + 1
                    out[name] = arr
                else:
                    out[name] = blob[p:blob.index(b"\0", p)].decode("utf-8", "replace")
        except (ValueError, struct.error):
            continue
    return out


def package_list(reg: Registry, resolved: dict) -> dict:
    """{binary name: {evr, srpm, src, changelog[]}} for a single image."""
    cands = [l for l in resolved["layers"] if any(CHUNK_MATCH in c for c in l["components"])]
    if not cands:
        raise SystemExit(T(
            "no standalone rpmdb chunk in this image (needs chunkah 'bigfiles' layout); "
            "use `layers` or --exact 0 instead",
            "此镜像中没有独立的 rpmdb chunk（需要 chunkah 'bigfiles' 布局）；"
            "请改用 `layers` 或 --exact 0"))
    cands.sort(key=lambda l: l["size"])
    path = reg.extract_member(cands[0], CHUNK_MATCH)
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = con.execute("select blob from Packages").fetchall()
    except sqlite3.OperationalError:
        raise SystemExit(T("unexpected rpmdb schema (no Packages table)",
                           "rpmdb 结构不符合预期（没有 Packages 表）"))
    con.close()
    try:
        os.unlink(path)
    except OSError:
        pass
    pkgs: dict = {}
    for (blob,) in rows:
        h = read_header(blob)
        name = h.get("name")
        if not name or not h.get("version"):
            continue
        srpm = (h.get("sourcerpm") or "").replace(".src.rpm", "")
        src = re.sub(r"-\d[^-]*-[^-]*$", "", srpm) or name
        times = h.get("changelogtime") or []
        names = h.get("changelogname") or []
        texts = h.get("changelogtext") or []
        if isinstance(texts, str):
            texts = [texts]
        if isinstance(names, str):
            names = [names]
        chlog = [{"time": (times[i] if i < len(times) else 0),
                  "who": (names[i] if i < len(names) else ""),
                  "text": t} for i, t in enumerate(texts)]
        e = {"name": name, "version": h.get("version", ""), "release": h.get("release", ""),
             "epoch": h.get("epoch", ""), "arch": h.get("arch", ""), "srpm": srpm, "src": src,
             "changelog": chlog}
        e["evr"] = e["version"] + "-" + e["release"]
        e["nvr"] = f"{name}-{e['version']}-{e['release']}"
        old = pkgs.get(name)
        if old is None or evr_cmp(e, old) > 0:
            pkgs[name] = e
    return pkgs


# --------------------------------------------------------------------------- #
# Fedora Bodhi: errata for a build (type=security, severity, CVE list)
# --------------------------------------------------------------------------- #
class Bodhi:
    BASE = "https://bodhi.fedoraproject.org"

    def __init__(self, cache_dir=None, sleep=0.3, max_calls=80, ttl=6 * 3600):
        self.cache_dir, self.sleep, self.max_calls, self.ttl = cache_dir, sleep, max_calls, ttl
        self.calls, self._mem = 0, {}
        self.failed = 0          # queries that errored => verdict must not claim "clean"
        self.skipped = 0         # queries we never made because of --max-bodhi
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    def _cf(self, key):
        return os.path.join(self.cache_dir, "bodhi-" + re.sub(r"\W+", "_", key) + ".json") \
            if self.cache_dir else None

    def updates_for_src(self, src: str, release: str) -> list:
        key = f"{src}-{release}"
        cf = self._cf(key)
        if cf and os.path.exists(cf) and time.time() - os.path.getmtime(cf) < self.ttl:
            return json.load(open(cf))
        if key in self._mem:
            return self._mem[key]
        res: list = []
        if self.calls >= self.max_calls:
            self.skipped += 1
            return res
        if True:
            self.calls += 1
            url = f"{self.BASE}/updates/?" + urllib.parse.urlencode(
                {"packages": src, "releases": release, "rows_per_page": "100"})
            ok = False
            try:
                with urllib.request.urlopen(url, timeout=40) as r:
                    data = json.load(r)
                ok = True
                for u in data.get("updates", []):
                    res.append({
                        "alias": u.get("alias"), "type": u.get("type"),
                        "severity": u.get("severity"), "status": u.get("status"),
                        "title": u.get("title"), "notes": (u.get("notes") or "")[:1500],
                        "cves": [c.get("name") for c in (u.get("cves") or [])
                                 if isinstance(c, dict)],
                        "date_approved": u.get("date_approved"),
                        "nvrs": [b.get("nvr") for b in (u.get("builds") or [])],
                    })
            except Exception as ex:
                self.failed += 1
                log(T(f"  ! bodhi lookup failed for {src}: {ex}",
                      f"  ！查询 Bodhi 失败：{src}：{ex}"))
            # never cache a failed query: an empty answer would blind later runs
            if cf and ok:
                _atomic_write_json(cf, res)
            time.sleep(self.sleep)
        self._mem[key] = res
        return res


SEV_RANK = {"critical": 4, "urgent": 4, "important": 3, "high": 3, "moderate": 2,
            "medium": 2, "low": 1, "none": 0, "unspecified": 0, "": 0}


def nvr_candidates(pkg: dict) -> list:
    """NEVRA spellings to try against Fedora errata (secureblue rebuilds some packages)."""
    out = [pkg["nvr"]]
    for pat in (r"\.secureblue\.\d+", r"\+fedora\.\d+$", r"\.sb\d+"):
        r = re.sub(pat, "", pkg["release"])
        if r != pkg["release"]:
            out.append(f"{pkg['name']}-{pkg['version']}-{r}")
    return out


def classify_change(old: dict | None, new: dict, rel: str, bodhi: Bodhi | None) -> dict:
    info = {"security": False, "cves": set(), "cves_dropped": set(), "aliases": [],
            "severities": [], "bodhi_type": None, "why": [], "erratum": None}

    def add_cves(text, into=None):
        for c in CVE_RE.findall(text or ""):
            (into if into is not None else info["cves"]).add(c)

    # (a) changelog entries that are new in this build: Fedora writes CVE ids there
    old_log = (old or {}).get("changelog", [])
    old_times = {c["time"] for c in old_log}
    new_log = new.get("changelog", [])
    for c in [x for x in new_log if x["time"] not in old_times][:15]:
        add_cves(c["text"])
        if SEC_WORDS_RE.search(c["text"] or ""):
            first = (c["text"] or "").strip().splitlines()
            info["why"].append("changelog/更新日志: " + (first[0][:90] if first else ""))
    # fixes that the new image *loses* (downgrade / rebuild without the patch)
    new_times = {c["time"] for c in new_log}
    for c in [x for x in old_log if x["time"] not in new_times][:20]:
        add_cves(c["text"], info["cves_dropped"])
    if info["cves"]:
        info["security"] = True
        info["why"].insert(0, "changelog CVEs/更新日志中的 CVE: " + ", ".join(sorted(info["cves"])[:8]))
    if info["cves_dropped"]:
        info["why"].insert(0, "DROPS fixes/丢失的修复: " + ", ".join(sorted(info["cves_dropped"])[:8]))

    # (b) the Fedora erratum that shipped the new build
    my_nvr = set(nvr_candidates(new))
    old_nvr = set(nvr_candidates(old)) if old else set()
    if bodhi is not None:
        for u in bodhi.updates_for_src(new["src"], rel):
            hit_new = my_nvr & set(u["nvrs"])
            hit_old = old_nvr & set(u["nvrs"])
            if not (hit_new or hit_old):
                continue
            info["aliases"].append(u["alias"])
            info["severities"].append((u.get("severity") or "").lower())
            add_cves(" ".join(u.get("cves") or []))
            add_cves(u.get("notes") or "")
            add_cves(u.get("title") or "")
            if hit_new:
                info["bodhi_type"] = u["type"]
                info["erratum"] = {"alias": u["alias"], "type": u["type"],
                                   "severity": u.get("severity"),
                                   "approved": u.get("date_approved"),
                                   "notes": (u.get("notes") or "")[:300]}
                if u["type"] == "security":
                    info["security"] = True
                    info["why"].append(
                        f"erratum/勘误 {u['alias']}: type=security severity={u.get('severity')} "
                        f"status={u.get('status')}")
    info["cves"] = sorted(info["cves"])
    info["cves_dropped"] = sorted(info["cves_dropped"])
    info["important_src"] = new["src"] in IMPORTANT_SRC
    info["sev_rank"] = max([SEV_RANK.get(s, 0) for s in info["severities"]] or [0])
    if info["sev_rank"] >= 3:
        info["security"] = True
    return info


# --------------------------------------------------------------------------- #
# analyses
# --------------------------------------------------------------------------- #
def chunk_map(img: dict) -> dict:
    m: dict = {}
    for l in img["layers"]:
        for c in l["components"]:
            m.setdefault(c, []).append(l)
    return m


def layer_diff(a: dict, b: dict) -> dict:
    da = {l["digest"]: l for l in a["layers"]}
    db = {l["digest"]: l for l in b["layers"]}
    changed = sorted((l for d, l in db.items() if d not in da), key=lambda l: -l["size"])
    dl_bytes = sum(l["size"] for d, l in db.items() if d not in da)
    pkgs = sorted({c[4:] for l in changed for c in l["components"] if c.startswith("rpm/")})
    total_b = sum(l["size"] for l in b["layers"])
    return {
        "chunks_a": len(da), "chunks_b": len(db), "chunks_changed": len(changed),
        "chunks_reused": len(db) - len(changed), "total_size_b": total_b,
        "download_bytes": dl_bytes, "download_pct": round(100 * dl_bytes / max(1, total_b)),
        "changed_packages_from_chunks": pkgs,
        "changed_chunks": [{"components": l["components"], "size": l["size"],
                            "stability": l["stability"]} for l in changed],
    }


def pkg_diff(pa: dict, pb: dict) -> dict:
    changed = []
    for n in sorted(set(pa) & set(pb)):
        x, y = pa[n], pb[n]
        if x["nvr"] == y["nvr"]:
            continue
        d = evr_cmp(x, y)
        changed.append({"name": n, "old": x, "new": y, "src": y["src"],
                        "dir": "downgrade" if d > 0 else "upgrade" if d < 0 else "rebuild"})
    return {
        "added": sorted(set(pb) - set(pa)),
        "removed": sorted(set(pa) - set(pb)),
        "changed": changed,
        "downgrades": [c for c in changed if c["dir"] == "downgrade"],
        "count_a": len(pa), "count_b": len(pb),
        "unchanged_count": len(set(pa) & set(pb)) - len(changed),
    }


def crosscheck_chunks(ldiff: dict, diff: dict, src_of: dict | None = None) -> dict:
    """Chunks moved but the NEVRA did not change => silent rebuild (kernel hardening
    bumps, rpm macros, file ordering...). Explains '700 MB and nothing changed'."""
    src_of = src_of or {}
    changed_versions = {c["name"] for c in diff["changed"]}
    changed_src = {c["src"] for c in diff["changed"]}
    silent = []
    for ch in ldiff["changed_chunks"]:
        pk = [c[4:] for c in ch["components"] if c.startswith("rpm/")]
        if not pk:
            continue
        # only single-package chunks give an unambiguous verdict; in a bundled chunk a
        # changed digest may be caused by any one of its members
        if len(ch["components"]) != 1 or pk[0] in changed_versions or \
           pk[0] in changed_src or src_of.get(pk[0]) in changed_src:
            continue
        silent.append((pk[0], ch["size"]))
    by_size: dict = {}
    for n, s in silent:
        by_size[n] = max(by_size.get(n, 0), s)
    nonpkg = []
    for ch in ldiff["changed_chunks"]:
        junk = [c for c in ch["components"] if not c.startswith("rpm/")]
        if junk and all(not c.startswith("rpm/") for c in ch["components"]):
            nonpkg.append({"components": junk, "size": ch["size"]})
    return {"silent_rebuilds": sorted(by_size.items(), key=lambda kv: -kv[1]),
            "non_package_chunks": nonpkg,
            "non_package_bytes": sum(x["size"] for x in nonpkg)}


def fedora_release(pkgs: dict) -> str:
    for p in pkgs.values():
        m = re.search(r"\.fc(\d+)", p["release"])
        if m:
            return "F" + m.group(1)
    return "F44"


def verdict_of(diff: dict, ldiff: dict, meta: dict, xc: dict | None = None,
               backlog: list | None = None, bodhi_state: dict | None = None) -> dict:
    """Turn the raw diff into a recommendation. Grouped by *source* package so that a
    21-subpackage linux-firmware bump is not counted as 21 separate events.
    Bilingual: sets headline (English) and headline_zh (中文)."""
    xc = xc or {}
    groups = group_by_src(diff["changed"])
    sec = [g for g in groups if g["security"] and not g["downgrade"]]
    down = [g for g in groups if g["downgrade"]]
    lost = [g for g in groups if g["dropped"]]
    imp = [g for g in groups if g["important"] and not g["security"]]
    cves = sorted({c for g in sec for c in g["cves"]})
    sev = max([g["sev_rank"] for g in sec] or [0])
    kernel_moved = bool(meta.get("kernel_a")) and meta.get("kernel_a") != meta.get("kernel_b")
    silent = xc.get("silent_rebuilds") or []
    silent_key = [n for n, _ in silent[:60] if n.startswith("kernel") or n in IMPORTANT_SRC]
    n_bin = len(diff["changed"])
    v = {"level": "skip", "headline": "", "headline_zh": "", "changed_src_count": len(groups),
         "changed_pkg_count": n_bin, "security_src": [g["src"] for g in sec],
         "security_pkgs": sorted({p["name"] for g in sec for p in g["pkgs"]}),
         "important_pkgs": sorted({p["name"] for g in imp for p in g["pkgs"]}),
         "cves": cves, "cves_dropped": sorted({c for g in lost for c in g["dropped"]}),
         "downgrades": [g["src"] for g in down], "severity_rank": sev,
         "kernel_changed": kernel_moved, "silent_rebuilds": [n for n, _ in silent],
         "silent_important": silent_key, "non_package_bytes": xc.get("non_package_bytes", 0),
         "download_human": human(ldiff["download_bytes"]),
         "backlog_count": len(backlog or [])}
    same_input = bool(meta.get("inputhash_a")) and meta["inputhash_a"] == meta.get("inputhash_b")
    v["same_inputhash"] = same_input
    if same_input and not sec and not down and not lost:
        v["level"] = "no-change"
        v["headline"] = (f"identical rpm-ostree inputhash ({str(meta['inputhash_a'])[:12]}) - "
                         "this image was composed from exactly the same package inputs as the "
                         "previous one; "
                         f"{len(xc.get('silent_rebuilds') or [])} chunk(s) were merely "
                         f"re-emitted. Updating would cost {v['download_human']} and change "
                         "nothing observable")
        v["headline_zh"] = (f"rpm-ostree inputhash 完全相同（{str(meta['inputhash_a'])[:12]}）——"
                            "此镜像与上一版由完全相同的软件包输入构成；"
                            f"{len(xc.get('silent_rebuilds') or [])} 个 chunk 只是被重新发出。"
                            f"更新需花费 {v['download_human']} 下载量，却不会带来任何可观察的变化")
        return v
    if sec:
        v["level"] = "update-now"
        top = ", ".join(f"{g['src']} ({', '.join(g['cves'][:2]) or 'security erratum 安全勘误'})"
                        for g in sec[:4])
        v["headline"] = (f"{plural(len(sec), 'source package')} "
                         f"{'gains' if len(sec) == 1 else 'gain'} security fixes: {top}"
                         + (f" — {len(cves)} CVE(s) total" if cves else "")
                         + (". Kernel version also changed" if kernel_moved else ""))
        v["headline_zh"] = (f"{len(sec)} 个源码包获得安全修复：{top}"
                            + (f" —— 共 {len(cves)} 个 CVE" if cves else "")
                            + ("；内核版本也已变化" if kernel_moved else ""))
        if sev >= 3:
            v["headline"] = "HIGH/CRITICAL severity fix present. " + v["headline"]
            v["headline_zh"] = "存在 HIGH/CRITICAL（高/严重）级别修复。" + v["headline_zh"]
    elif kernel_moved or imp or silent_key:
        v["level"] = "consider"
        bits, bits_zh = [], []
        if kernel_moved:
            bits.append(f"kernel {meta['kernel_a']} → {meta['kernel_b']}")
            bits_zh.append(f"内核 kernel {meta['kernel_a']} → {meta['kernel_b']}")
        if imp:
            bits.append("version bump in security-sensitive packages: "
                        + ", ".join(g["src"] for g in imp[:5]))
            bits_zh.append("安全敏感软件包版本升级：" + ", ".join(g["src"] for g in imp[:5]))
        if silent_key:
            bits.append("rebuilt (identical version): " + ", ".join(silent_key[:5]))
            bits_zh.append("重建（版本相同）：" + ", ".join(silent_key[:5]))
        v["headline"] = ("no CVE/erratum found for this delta, but " + "; ".join(bits)
                         + ". Reasonable to skip if the download matters to you")
        v["headline_zh"] = ("此差异未发现 CVE/勘误，但涉及：" + "；".join(bits_zh)
                            + "。如果下载量对你很重要，可以合理地跳过")
    else:
        tail = tail_zh = ""
        if v["non_package_bytes"]:
            tail = (f"; {human(v['non_package_bytes'])} of the download is non-package churn "
                    f"(initramfs / ostree metadata)")
            tail_zh = (f"；下载中有 {human(v['non_package_bytes'])} 属于非软件包内容"
                       f"（initramfs / ostree 元数据）")
        v["level"] = "skip"
        v["headline"] = (f"routine churn: {plural(len(groups), 'source package')} "
                         f"({n_bin} binary) bumped, {len(diff['added'])} added / "
                         f"{len(diff['removed'])} removed, no CVE and no security erratum"
                         + (f", {len(silent)} chunk(s) rebuilt with identical versions" if silent else "")
                         + tail)
        v["headline_zh"] = (f"常规更新：{len(groups)} 个源码包（{n_bin} 个二进制包）升级，"
                            f"新增 {len(diff['added'])} 个 / 移除 {len(diff['removed'])} 个，"
                            "无 CVE、无安全勘误"
                            + (f"，{len(silent)} 个 chunk 以相同版本重建" if silent else "")
                            + tail_zh)
    if down:
        dl_txt = ", ".join(f"{g['src']} ({g['old_evr']} → {g['new_evr']})"
                           for g in down[:3])
        v["headline"] += (" | WARNING: this update downgrades " + dl_txt)
        v["headline_zh"] += (" ｜ 警告：此次更新会降级 " + dl_txt)
    if bodhi_state:
        bad, miss = bodhi_state.get("failed", 0), bodhi_state.get("skipped", 0)
        off = bodhi_state.get("disabled", 0)
        if bad or miss or off:
            why, why_zh = [], []
            if off:
                why.append("Bodhi lookups were disabled (--no-bodhi)")
                why_zh.append("Bodhi 查询已被禁用 (--no-bodhi)")
            if bad:
                why.append(f"{bad} Bodhi query(ies) failed")
                why_zh.append(f"{bad} 次 Bodhi 查询失败")
            if miss:
                why.append(f"{miss} package(s) were not queried (--max-bodhi)")
                why_zh.append(f"{miss} 个软件包未被查询 (--max-bodhi)")
            v["headline"] += " | CAUTION: errata coverage incomplete - " + "; ".join(why) \
                             + ", so 'no security fixes' is not proven"
            v["headline_zh"] += " ｜ 注意：勘误覆盖不完整 —— " + "；".join(why_zh) \
                                + "，因此“无安全修复”并未被证实"
            if v["level"] == "skip":
                v["level"] = "consider"
    if v["cves_dropped"]:
        drop_txt = ", ".join(v["cves_dropped"][:6])
        v["headline"] += (" | WARNING: fixes that disappear: " + drop_txt)
        v["headline_zh"] += (" ｜ 警告：会消失的修复：" + drop_txt)
        if v["level"] == "skip":
            v["level"] = "consider"
    if backlog:
        hi = [r for r in backlog if (r.get("severity") or "").lower() in
              ("critical", "important", "high", "urgent")]
        if hi and v["level"] != "update-now":
            v["level"] = "consider"
        v["headline"] += (f" | note: the image still misses {len(backlog)} published stable "
                          f"security update(s){' (' + str(len(hi)) + ' important+)' if hi else ''}")
        v["headline_zh"] += (f" ｜ 提示：该镜像仍缺少 {len(backlog)} 个已发布的 stable 安全更新"
                             f"{'（其中 ' + str(len(hi)) + ' 个为重要及以上级别）' if hi else ''}")
    return v


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
ICON = {"update-now": "[!] UPDATE NOW / [!] 立即更新",
        "consider": "[~] OPTIONAL / [~] 可选更新",
        "skip": "[ok] SKIP OK / [ok] 可跳过",
        "no-change": "[ok] REBUILD ONLY - SKIP / [ok] 仅重建——可跳过",
        "no-update": "[ok] NO NEW BUILD / [ok] 无新构建",
        "unknown": "[?] UNKNOWN / [?] 未知"}


def group_by_src(changed: list) -> list:
    """Collapse binary subpackages that come from the same source build."""
    groups: dict = {}
    for c in changed:
        key = c.get("src") or c["name"]
        g = groups.setdefault(key, {"src": key, "pkgs": [], "security": False,
                                    "cves": set(), "dropped": set(), "aliases": [],
                                    "why": [], "sev_rank": 0, "important": False,
                                    "downgrade": False})
        g["pkgs"].append(c)
        cls = c.get("cls") or {}
        g["security"] = g["security"] or bool(cls.get("security"))
        g["important"] = g["important"] or bool(cls.get("important_src"))
        g["cves"].update(cls.get("cves") or [])
        g["dropped"].update(cls.get("cves_dropped") or [])
        for a in cls.get("aliases") or []:
            if a not in g["aliases"]:
                g["aliases"].append(a)
        for w in cls.get("why") or []:
            if w not in g["why"]:
                g["why"].append(w)
        g["sev_rank"] = max(g["sev_rank"], cls.get("sev_rank") or 0)
        if c["dir"] == "downgrade":
            g["downgrade"] = True
    out = sorted(groups.values(), key=lambda g: (-g["sev_rank"], g["src"]))
    for g in out:
        g["cves"] = sorted(g["cves"])
        g["dropped"] = sorted(g["dropped"])
        o, n = g["pkgs"][0]["old"], g["pkgs"][0]["new"]
        g["old_evr"], g["new_evr"] = o.get("evr", "?"), n.get("evr", "?")
        g["same_evr"] = all(p["old"]["evr"] == g["old_evr"] and p["new"]["evr"] == g["new_evr"]
                            for p in g["pkgs"])
    return out


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def shortref(ref) -> str:
    """sha256:<64 hex> is noisy in a table; the first 12 hex chars are unique enough."""
    ref = str(ref or "")
    if DIGEST_RE.match(ref):
        return "sha256:" + ref.split(":")[1][:12] + "…"
    return ref


def fmt_pkgs(g: dict) -> str:
    names = [p["name"] for p in g["pkgs"]]
    if len(names) == 1:
        return f"`{names[0]}`"
    head = ", ".join(f"`{x}`" for x in names[:3])
    return f"{head} +{len(names)-3} subpackages/子包" if len(names) > 3 else head


def render_markdown(subject, a, b, diff, ldiff, verdict, notes, xc=None, backlog=None) -> str:
    xc = xc or {}
    L = []
    W = L.append
    sec_n = len(verdict["security_pkgs"])
    W(f"# {subject}")
    W("")
    W(f"## Verdict 结论: {ICON.get(verdict['level'], verdict['level'])}")
    W("")
    W(verdict["headline"])
    if verdict.get("headline_zh"):
        W(verdict["headline_zh"])
    W("")
    W(f"**If you update, you download {human(ldiff['download_bytes'])}** — "
      f"{ldiff['chunks_changed']} of {ldiff['chunks_b']} chunks changed, "
      f"{ldiff['chunks_reused']} are already on disk and get reused. "
      f"(full image: {human(ldiff['total_size_b'])}, so this update = {ldiff['download_pct']}%)")
    W(f"**如果现在更新，需要下载 {human(ldiff['download_bytes'])}** —— "
      f"{ldiff['chunks_b']} 个 chunk 中有 {ldiff['chunks_changed']} 个发生变化，"
      f"{ldiff['chunks_reused']} 个已在本地、会被复用。"
      f"（完整镜像为 {human(ldiff['total_size_b'])}，本次更新约占 {ldiff['download_pct']}%）")
    W("")
    W("| | previous 上一版 | new 新版 |")
    W("|---|---|---|")
    W(f"| compared refs 对比引用 | `{shortref(a['ref'])}` | `{shortref(b['ref'])}` |")
    W(f"| image version 镜像版本 | {a['annotations'].get('org.opencontainers.image.version', '?')} "
      f"| {b['annotations'].get('org.opencontainers.image.version', '?')} |")
    W(f"| built (UTC) 构建时间 | {a.get('created') or '?'} | {b.get('created') or '?'} |")
    W(f"| kernel 内核 | {a['annotations'].get('ostree.linux', '?')} | {b['annotations'].get('ostree.linux', '?')} |")
    W(f"| rpm-ostree inputhash 输入哈希 | `{(a['annotations'].get('rpmostree.inputhash') or '')[:12]}` "
      f"| `{(b['annotations'].get('rpmostree.inputhash') or '')[:12]}` |")
    W(f"| manifest digest 摘要 | `{a['digest'][:19]}…` | `{b['digest'][:19]}…` |")
    W(f"| packages in image 镜像内软件包数 | {diff.get('count_a', '?')} | {diff.get('count_b', '?')} |")
    W("")
    if (a["annotations"].get("rpmostree.inputhash") and a["annotations"].get("rpmostree.inputhash")
            == b["annotations"].get("rpmostree.inputhash")):
        W("> **Both images were composed from identical package inputs (same")
        W("> `rpmostree.inputhash`)** - byte differences here are rebuild noise, not changes.")
        W("> **两个镜像由完全相同的软件包输入构成（`rpmostree.inputhash` 相同）**——")
        W("> 这里的字节差异只是重建噪声，并非真实变化。")
        W("")
    notes = list(dict.fromkeys(notes))
    for n in notes:
        W(f"> {n}")
    if notes:
        W("")

    changed = diff["changed"]
    groups = group_by_src(changed)
    g_down = [g for g in groups if g["downgrade"]]
    g_lost = [g for g in groups if g["dropped"]]
    g_sec = [g for g in groups if g["security"] and not g["downgrade"]]
    g_imp = [g for g in groups if g["important"] and not g["security"] and not g["downgrade"]]
    g_other = [g for g in groups if g not in g_sec and g not in g_imp
               and g not in g_down and g not in g_lost]

    if g_down:
        W(f"## Downgrades in this update ({len(g_down)}) — read first"
          f" / 本次更新中的降级（{len(g_down)}）——请先阅读")
        W("")
        for g in g_down:
            W(f"- **{g['src']}**: {g['old_evr']} → {g['new_evr']} "
              f"({len(g['pkgs'])} package(s)/包)"
              + (" — this *reverts* a published erratum / 这会*回退*已发布的勘误: "
                 + ", ".join(g["aliases"][:2])
                 if g["security"] else ""))
        W("")
    if g_lost:
        W(f"## Fixes that this update REMOVES ({len(g_lost)})"
          f" / 本次更新会移除的修复（{len(g_lost)}）")
        W("")
        for g in g_lost:
            W(f"- `{g['src']}`: no longer mentions / 不再提及 {', '.join(g['dropped'][:8])}")
        W("")

    if g_sec:
        W(f"## Security-relevant changes ({len(g_sec)} source package(s), "
          f"{sec_n} binary package(s))"
          f" / 安全相关变更（{len(g_sec)} 个源码包，{sec_n} 个二进制包）")
        W("")
        W("| source package 源码包 | old → new 旧 → 新 | CVEs | errata / evidence 勘误/依据 |")
        W("|---|---|---|---|")
        for g in g_sec:
            ev = "; ".join(g["why"])[:190] or ", ".join(g["aliases"]) or "—"
            W(f"| {fmt_pkgs(g)} ({g['src']}) | {g['old_evr']} → **{g['new_evr']}** | "
              f"{', '.join(g['cves'][:6]) or '—'} | {ev} |")
        W("")
    if g_imp:
        W(f"## Bumps in security-sensitive packages, no CVE mentioned ({len(g_imp)})"
          f" / 安全敏感包版本升级、未提及 CVE（{len(g_imp)}）")
        W("")
        for g in g_imp:
            extra = f" (errata 勘误: {', '.join(g['aliases'][:2])})" if g["aliases"] else ""
            W(f"- `{g['src']}` {g['old_evr']} → {g['new_evr']} — {len(g['pkgs'])} pkg(s)/包"
              f"{extra}; {'; '.join(g['why'])[:160] or 'no security changelog entry / 无安全相关更新日志'}")
        W("")
    if g_other:
        W(f"## Routine bumps ({len(g_other)} source package(s), "
          f"{len(g_other) and sum(len(g['pkgs']) for g in g_other)} binary)"
          f" / 常规版本升级（{len(g_other)} 个源码包，{sum(len(g['pkgs']) for g in g_other)} 个二进制包）")
        W("")
        W("| source package 源码包 | binary packages 二进制包 | old → new 旧 → 新 |")
        W("|---|---|---|")
        for g in g_other:
            W(f"| {g['src']} | {fmt_pkgs(g)} | {g['old_evr']} → {g['new_evr']} |")
        W("")
    if not changed and isinstance(diff.get("count_a"), int):
        W("## No package version changed at all / 没有任何软件包版本发生变化")
        W("")
        W("Every package in both images has the same NEVRA — the delta is entirely "
          "rebuilt content / metadata churn. / "
          "两个镜像中所有软件包的 NEVRA 完全一致——差异全部来自重建内容 / 元数据变动。")
        W("")

    if diff["added"] or diff["removed"]:
        W("## Package set / 软件包集合")
        if diff["added"]:
            W(f"added 新增 ({len(diff['added'])}): "
              + ", ".join(f"`{x}`" for x in diff["added"][:40]))
        if diff["removed"]:
            W(f"removed 移除 ({len(diff['removed'])}): "
              + ", ".join(f"`{x}`" for x in diff["removed"][:40]))
        W("")

    silent = xc.get("silent_rebuilds") or []
    if silent:
        W(f"## Rebuilt with the *same* version ({len(silent)})"
          f" / 版本相同但被重建（{len(silent)}）")
        W("")
        W("These chunks changed byte-for-byte while the package version did not. That is "
          "usually a secureblue rebuild, a toolchain/macro change, or file re-ordering — "
          "it costs download bytes but carries no upstream changelog entry. / "
          "这些 chunk 的字节变了，但软件包版本没变。通常是一次 secureblue 重建、工具链/macro 变化"
          "或文件重排——会消耗下载量，却没有对应的上游更新日志。")
        W("")
        for n, s in silent[:20]:
            W(f"- `{n}` — {human(s)}")
        if len(silent) > 20:
            W(f"- … and {len(silent)-20} more / ……另有 {len(silent)-20} 个")
        W("")
    if xc.get("non_package_chunks"):
        W("## Changes that are not packages / 非软件包的变更")
        W("")
        for ch in xc["non_package_chunks"]:
            W(f"- {human(ch['size'])} — {', '.join(c.replace('bigfiles/', '') for c in ch['components'])[:120]}")
        W("")

    if backlog:
        W(f"## What your (current or new) image is still missing ({len(backlog)})"
          f" / 你的（当前或新）镜像仍缺少的更新（{len(backlog)}）")
        W("")
        W("Published **stable** Fedora security updates whose build is newer than the one in "
          "the image — i.e. exposure that skipping this update does not change, but that you "
          "may want to know about. / "
          "已发布的 **stable** Fedora 安全更新，其构建比镜像内的更新——"
          "即无论是否跳过本次更新都存在的暴露面，但你应当知情。")
        W("")
        W("| package 软件包 | in image 镜像内 | newer stable build 新 stable 构建 | severity 严重度 | erratum 勘误 |")
        W("|---|---|---|---|---|")
        for r in backlog[:25]:
            W(f"| `{r['name']}` | {r['have']} | **{r['want']}** | {r['severity'] or '?'} "
              f"| {r['alias']} |")
        W("")

    if ldiff["changed_chunks"]:
        W(f"## Chunks you would re-download ({len(ldiff['changed_chunks'])})"
          f" / 需要重新下载的 chunk（{len(ldiff['changed_chunks'])}）")
        W("")
        for ch in ldiff["changed_chunks"][:15]:
            comps = [c.replace("rpm/", "").replace("bigfiles/", "≈") for c in ch["components"]][:5]
            more = len(ch["components"]) - len(comps)
            W(f"- {human(ch['size'])} — {', '.join(comps)}"
              + (f" +{more} pkgs/包" if more > 0 else ""))
        if len(ldiff["changed_chunks"]) > 15:
            W(f"- … {len(ldiff['changed_chunks'])-15} smaller chunks"
              f" / ……另有 {len(ldiff['changed_chunks'])-15} 个更小的 chunk")
        W("")
    W("---")
    W("Generated by `sbwatch`: registry manifests + the image's `rpmdb.sqlite` chunk only. "
      "Nothing was pulled, and no credentials were used. / "
      "由 `sbwatch` 生成：仅使用了 registry manifest 与镜像的 `rpmdb.sqlite` chunk。"
      "未拉取完整镜像，也未使用任何凭据。")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# "am I exposed even if I skip?" — published stable security updates that the
# image does not contain yet (Fedora Bodhi, capped number of queries)
# --------------------------------------------------------------------------- #
BACKLOG_POOL = {
    "kernel", "glibc", "openssl", "nss", "systemd", "sudo", "polkit", "rpm-ostree",
    "ostree", "selinux-policy", "container-selinux", "pam", "shadow-utils", "openssh",
    "curl", "rpm", "grub2", "shim", "mutter", "gnome-shell", "webkitgtk", "firefox",
    "thunderbird", "trivalent", "trivalent-native", "trivalent-binary-packaging",
    "flatpak", "flatpak-selinux", "xdg-desktop-portal", "pipewire", "xorg-x11-server",
    "usbguard", "bubblewrap", "fwupd", "bluez", "cups", "avahi", "libarchive", "gnutls",
    "expat", "libcap", "audit", "krb5", "bind", "dnsmasq", "unbound", "nginx",
    "polkit-qt", "kde-plasma-desktop", "qt6-qtbase", "giolang-github", "golang",
    "python3", "python-pip", "git", "git-lfs", "wireguard-tools", "openvpn",
    "wireless-regdog", "linux-firmware", "amd-gpu-firmware", "runc", "crun", "cri-o",
    "podman", "skopeo", "composefs", "veritysetup", "cryptsetup", "keyutils",
}


def security_backlog(pkgs: dict, rel: str, bodhi: Bodhi, limit: int = 45) -> list:
    """Stable Fedora security errata whose build is newer than what the image ships."""
    want = {}
    for n, p in pkgs.items():
        if p["src"] in BACKLOG_POOL:
            want.setdefault(p["src"], []).append((n, p))
    rows = []
    for src in sorted(want)[:limit]:
        ups = bodhi.updates_for_src(src, rel)
        done = False
        for u in ups:
            if done:
                break
            if u.get("type") != "security" or u.get("status") != "stable":
                continue
            for n, p in want[src]:
                best = None
                for b in u["nvrs"]:
                    parts = b.rsplit("-", 2)
                    if len(parts) != 3:
                        continue
                    bn, bv, br = parts
                    if bn != n:                       # exact binary name, not a prefix
                        continue
                    cand = {"name": n, "version": bv, "release": br}
                    if evr_cmp(p, cand) < 0 and (best is None or evr_cmp(best, cand) < 0):
                        best = cand
                if best is None:
                    continue
                rows.append({"name": n, "src": src, "have": p["evr"],
                             "want": f"{best['version']}-{best['release']}",
                             "alias": u["alias"], "severity": u.get("severity"),
                             "cves": (u.get("cves") or [])[:6],
                             "notes": (u.get("notes") or "")[:200]})
                done = True
            if done:
                break
    order = {"critical": 4, "urgent": 4, "important": 3, "high": 3, "moderate": 2, "low": 1}
    rows.sort(key=lambda r: -order.get((r["severity"] or "").lower(), 0))
    return rows


def cmd_backlog(args):
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    img = resolve(reg, args.ref, tks)
    maybe_verify_resolved(reg, img, args)
    cache_dir = args.cache_dir or os.path.expanduser("~/.cache/sbwatch")
    notes: list = []
    pkgs = load_pkglist(reg, img, args.ref, cache_dir, notes)
    rel = fedora_release(pkgs)
    bodhi = Bodhi(cache_dir=cache_dir, max_calls=args.max_bodhi)
    rows = security_backlog(pkgs, rel, bodhi, limit=args.max_bodhi)
    ver = img["annotations"].get("org.opencontainers.image.version", "?")
    print(f"{args.image}:{args.ref}  version 版本 {ver}  ({rel})")
    print(T(f"{len(rows)} package(s) in this image are behind a published STABLE security update",
            f"此镜像中有 {len(rows)} 个软件包落后于已发布的 STABLE 安全更新") + "\n")
    for r in rows:
        print(f"  {r['name']:28} {r['have']:>26}  ->  {r['want']:<26} "
              f"{(r['severity'] or '?'):9} {r['alias']}")
        if r["notes"]:
            print(f"  {'':28}{'':26}     {r['notes'].splitlines()[0][:110]}")
    if not rows:
        print("  none — as far as Fedora's stable repo is concerned this image is current "
              "(for the packages we checked) / 无 —— 就 Fedora stable 仓库而言，"
              "该镜像（在我们检查的软件包范围内）已是最新")
    if args.json_out:
        json.dump({"ref": args.ref, "digest": img["digest"], "version": ver,
                   "behind": rows}, open(args.json_out, "w"), indent=1)
    return 1 if any((r["severity"] or "").lower() in ("critical", "important", "high",
                                                      "urgent") for r in rows) else 0


# --------------------------------------------------------------------------- #
# build history
#
# secureblue rebuilds on every push to `live`, so one day can contain several
# images that share the same version string (e.g. three builds on 2026-09-08,
# all `44.20260908.0`).  All *named* tags are mutable pointers: `20260908`,
# `44`, `<shortsha>-44` and `latest` all get repointed by the next push, so you
# cannot find "the build before this one" by looking at tags.
#
# What is immutable is (a) the digest and (b) ghcr's cosign attachment tags:
# every push adds `sha256-<image digest>.sig` / `.att`.  Those give a complete
# per-build list from the registry alone - no GitHub token, no log access.
# --------------------------------------------------------------------------- #
DATED_RE = re.compile(r"^\d{8}(-\d+)?$")
SHATAG_RE = re.compile(r"^[0-9a-f]{7,10}(-\d+)?$")
SIGTAG_RE = re.compile(r"^sha256-([0-9a-f]{64})\.sig$")
BUILD_NOISE = re.compile(r"(integrationtest|^pr-|^br-|^sha256-)")


def list_tags(reg: Registry, max_pages: int = 12) -> list:
    """All tags of the repo. ghcr returns them in push order; pages via Link header."""
    out, url = [], f"https://{reg.host}/v2/{reg.repo}/tags/list?n=1000"
    for _ in range(max_pages):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            tok = reg._token()
            if tok:
                req.add_header("Authorization", "Bearer " + tok)
            with urllib.request.urlopen(req, timeout=reg.timeout) as r:
                body, hdrs = r.read(), r.headers
        except Exception as e:
            log(f"  ! tag list stopped: {e}")
            break
        out += json.loads(body).get("tags", []) or []
        nxt = re.search(r"<([^>]+)>;\s*rel=\"next\"", hdrs.get("Link") or "")
        if not nxt:
            break
        url = nxt.group(1)
        if url.startswith("/"):
            url = f"https://{reg.host}{url}"
    return out


def build_history(reg: Registry, tks: list, scan: int = 12, days: int = 7,
                  to: str = "latest") -> list:
    """Newest-first list of the images that were actually pushed to this repo.

    Discovery goes through ghcr's cosign attachment tags (`sha256-<digest>.sig`,
    one per push): they are the only per-build record that never gets repointed.
    Entries that resolve to a platform manifest instead of a multi-arch index are
    skipped, so each build appears exactly once, for the architecture asked for.

    record = {digest, created, version, inputhash, kernel, image, tags[],
              from_prev, same_input_as_prev}
    """
    tags = list_tags(reg)
    cur = resolve(reg, to, tks)
    sigs = [m.group(1) for m in (SIGTAG_RE.match(t) for t in tags) if m]
    recs: dict = {cur["index_digest"]: {
        "digest": cur["index_digest"], "created": cur.get("created"),
        "version": cur["annotations"].get("org.opencontainers.image.version"),
        "inputhash": cur["annotations"].get("rpmostree.inputhash"),
        "kernel": cur["annotations"].get("ostree.linux"), "image": cur, "tags": [to]}}
    for hexdig in reversed(sigs[-(scan * 8):]):
        if len(recs) >= scan:
            break
        d = "sha256:" + hexdig
        if d in recs or ("sha256:" + hexdig) in recs:
            continue
        try:
            img = resolve(reg, d, tks, light=True)
        except Exception:
            continue
        if not img.get("is_index"):
            continue
        recs[img["index_digest"]] = {
            "digest": img["index_digest"], "created": img.get("created"),
            "version": img["annotations"].get("org.opencontainers.image.version"),
            "inputhash": img["annotations"].get("rpmostree.inputhash"),
            "kernel": img["annotations"].get("ostree.linux"), "image": img, "tags": []}
    if days:                      # label: which dated tag currently points at a row
        for t in sorted({t for t in tags if DATED_RE.match(t)})[-days:]:
            try:
                img = resolve(reg, t, tks, light=True)
            except Exception:
                continue
            r = recs.get(img["index_digest"])
            if r is not None and t not in r["tags"]:
                r["tags"].append(t)
    out = sorted(recs.values(), key=lambda r: r.get("created") or "", reverse=True)
    for i, r in enumerate(out):
        if i + 1 < len(out):
            prev = out[i + 1]
            r["from_prev"] = layer_diff(prev["image"], r["image"])
            r["same_input_as_prev"] = bool(r["inputhash"]) and r["inputhash"] == prev["inputhash"]
        else:
            r["from_prev"] = None
            r["same_input_as_prev"] = False
    return out


def cmd_history(args):
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    rows = build_history(reg, tks, scan=args.scan, days=args.days, to=args.to)
    print(T(f"{args.image} ({args.arch}) — {len(rows)} most recent builds, oldest first.",
            f"{args.image} ({args.arch}) —— 最近 {len(rows)} 次构建，从旧到新显示。"))
    print("(named tags are mutable: several builds/day share one version string and the")
    print(" dated tag only points at the newest one, so compare by digest)")
    print("（命名标签是可变的：一天内多次构建共用同一个版本字符串，")
    print(" 日期标签只指向最新一次构建，因此请用 digest 来对比）")
    print("cost = bytes a client on the row above would download to reach this row / "
          "cost 下载量 = 上一行镜像的客户端升级到本行需下载的字节数\n")
    print(f"  {'created (UTC)':19} {'image version':15} {'input':11} "
          f"{'chunks':8} {'cost':>9}  {'kernel':22} refs")
    print(f"  {'创建时间 (UTC)':16} {'镜像版本':13} {'输入哈希':10} "
          f"{'chunk':8} {'下载量':>8}  {'内核':20} 引用")
    print("  " + "-" * 110)
    dup = 0
    for r in reversed(rows):
        ld = r.get("from_prev") or {}
        cost = human(ld.get("download_bytes", 0)) if ld else "—"
        ch = f"{ld.get('chunks_changed', '?')}/{ld.get('chunks_b', '?')}" if ld else "—"
        refs = ",".join(r["tags"][:2]) or f"sha256:{r['digest'].split(':')[1][:12]}"
        mark = ""
        if r.get("same_input_as_prev"):
            dup += 1
            mark = "   <= same inputhash as previous build: rebuild only / 与上次构建 inputhash 相同：仅重建"
        cur = " *CURRENT/当前" if r["tags"] and args.to in r["tags"] else ""
        print(f"  {(r.get('created') or '?')[:19]:19} {str(r['version'])[:15]:15} "
              f"{str(r['inputhash'])[:10]:11} {ch:8} {cost:>9}  "
              f"{str(r['kernel'])[:22]:22} {refs[:40]}{cur}{mark}")
    if dup:
        print(f"\n  {dup} of these builds changed no package input at all "
              f"(identical rpm-ostree inputhash) - updating to one of them buys nothing. / "
              f"其中 {dup} 次构建的软件包输入完全没有变化"
              f"（rpm-ostree inputhash 相同）——升级到它们没有任何收益。")
    oldest = rows[-1]
    print("\n  every image is addressable by its (immutable) digest, e.g. / "
          "每个镜像都可以用其（不可变的）digest 定位，例如：")
    print(f"    sbwatch.py diff sha256:{oldest['digest'].split(':')[1]} {args.to}")
    print(T("  (named tags are mutable - prefer digests when you want a specific build)",
            "  （命名标签可变——想指定某次构建时请优先使用 digest）"))
    return 0


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
DIGEST_RE = re.compile(r"^[A-Za-z0-9]+:[a-fA-F0-9]{32,}$")


def resolve(reg: Registry, ref: str, tok_holder: list, light: bool = False) -> dict:
    sep = "@" if DIGEST_RE.match(ref or "") else ":"
    r = Registry(f"{reg.host}/{reg.repo}{sep}{ref}", arch=reg.arch)
    if tok_holder:
        r._tok = tok_holder[0]
    out = r.resolve(ref, light=light)
    out["ref"] = ref
    tok_holder[0] = r._tok
    return out


def tag_exists(reg: Registry, tag: str) -> str | None:
    try:
        with reg._open(f"manifests/{tag}", MANIFEST_ACCEPT) as r:
            return r.headers.get("Docker-Content-Digest")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None


def cmd_tags(args):
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    cur = resolve(reg, args.to, tks)
    maybe_verify_resolved(reg, cur, args)
    print(f"{args.to} -> {cur['digest']}")
    print(f"  version 版本: {cur['annotations'].get('org.opencontainers.image.version')}")
    print(f"  created 构建时间: {cur.get('created')}   kernel 内核: {cur['annotations'].get('ostree.linux')}")
    print(f"  chunks 分块: {len(cur['layers'])}  total 总量: {human(sum(l['size'] for l in cur['layers']))}")
    print("\ndated tags (registry keeps ~4 weeks): / 日期标签（registry 约保留 4 周）：")
    now = time.time()
    for i in range(1, args.days + 1):
        d = time.strftime("%Y%m%d", time.gmtime(now - i * 86400))
        dig = tag_exists(reg, d)
        if not dig:
            continue
        same = "  == " + args.to if dig == cur.get("index_digest") else ""
        print(f"  {d}  {dig}{same}")
    return 0


def cmd_layers(args):
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    a, b = resolve(reg, args.a, tks), resolve(reg, args.b, tks)
    maybe_verify_resolved(reg, a, args)
    maybe_verify_resolved(reg, b, args)
    ld = layer_diff(a, b)
    if args.json:
        json.dump(ld, open(args.json, "w"), indent=1)
    print(f"{args.image}: {args.a} -> {args.b}")
    print(f"  version 版本: {a['annotations'].get('org.opencontainers.image.version')}"
          f" -> {b['annotations'].get('org.opencontainers.image.version')}")
    print(f"  kernel 内核:  {a['annotations'].get('ostree.linux')} -> {b['annotations'].get('ostree.linux')}")
    print(f"  chunks 分块:  {ld['chunks_a']} -> {ld['chunks_b']} | "
          f"{ld['chunks_changed']} changed 变化, {ld['chunks_reused']} reused 复用")
    print(f"  download 下载: {human(ld['download_bytes'])} ({ld['download_pct']}% of "
          f"{human(ld['total_size_b'])})")
    pk = ld["changed_packages_from_chunks"]
    print(f"  packages whose chunk changed / 所在 chunk 发生变化的软件包: {len(pk)}")
    for p in pk:
        print("     -", p)
    print(T("  biggest chunks to re-download:", "需要重新下载的最大 chunk："))
    for ch in ld["changed_chunks"][:12]:
        print(f"     {human(ch['size']):>9}  {' '.join(ch['components'])[:100]}")
    return 0


def cmd_pkgs(args):
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    r = resolve(reg, args.ref, tks)
    maybe_verify_resolved(reg, r, args)
    pkgs = package_list(reg, r)
    if args.json:
        slim = {k: {a: b for a, b in v.items() if a != "changelog"} for k, v in pkgs.items()}
        json.dump({"ref": args.ref, "digest": r["digest"],
                   "annotations": r["annotations"], "packages": slim},
                  open(args.json, "w"), indent=1)
        log(T(f"wrote {args.json}: {len(pkgs)} packages",
              f"已写入 {args.json}：{len(pkgs)} 个软件包"))
        return 0
    for n in sorted(pkgs):
        print(f"{n}\t{pkgs[n]['evr']}\t{pkgs[n]['arch']}\t{pkgs[n]['src']}")
    return 0


def _atomic_write_json(path: str, data) -> None:
    """ atomic write to avoid cache corruption on concurrent runs."""
    tmp = path + f".tmp.{os.getpid()}"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def load_pkglist(reg, img, ref, cache_dir, notes):
    os.makedirs(cache_dir, exist_ok=True)
    cf = os.path.join(cache_dir, f"pkglist-{img['digest'].replace(':', '')}.json")
    if os.path.exists(cf) and os.path.getsize(cf) > 10_000:
        try:
            notes.append(f"package list of `{ref}` served from `{cf}` (no download) / "
                         f"`{ref}` 的软件包列表来自缓存 `{cf}`（未下载）")
            return json.load(open(cf))
        except Exception:
            log(T(f"  ! cache {cf} corrupted, refetching",
                  f"  ！缓存 {cf} 已损坏，重新获取"))
    log(T(f"  fetching rpmdb chunk of {ref} ({img['digest'][:19]}…)",
          f"  正在获取 {ref} 的 rpmdb chunk（{img['digest'][:19]}…）"))
    pk = package_list(reg, img)
    _atomic_write_json(cf, pk)
    notes.append(f"package list of `{ref}` came from that image's `rpmdb.sqlite` chunk "
                 f"(~33 MB fetched, ~3.7 GiB avoided) / "
                 f"`{ref}` 的软件包列表来自该镜像的 `rpmdb.sqlite` chunk"
                 f"（仅下载约 33 MB，避免约 3.7 GiB）")
    return pk


def do_diff(args, ref_a: str, ref_b: str) -> dict:
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    a, b = resolve(reg, ref_a, tks), resolve(reg, ref_b, tks)
    maybe_verify_resolved(reg, a, args)
    maybe_verify_resolved(reg, b, args)
    ld = layer_diff(a, b)
    notes: list = []
    meta = {"kernel_a": a["annotations"].get("ostree.linux"),
            "kernel_b": b["annotations"].get("ostree.linux"),
            "inputhash_a": a["annotations"].get("rpmostree.inputhash"),
            "inputhash_b": b["annotations"].get("rpmostree.inputhash")}
    if not args.exact:
        diff = {"added": [], "removed": [], "downgrades": [], "changed": [],
                "count_a": "?", "count_b": "?", "unchanged_count": 0}
        diff["unchanged_count"] = ld["chunks_reused"]
        diff["chunk_candidates"] = ld["changed_packages_from_chunks"]
        xc = crosscheck_chunks(ld, diff)
        v = verdict_of(diff, ld, meta, xc)
        v["headline"] = ("chunk-level mode (manifests only, no rpmdb fetch): "
                         + v["headline"]
                         + f" | {len(ld['changed_packages_from_chunks'])} packages sit in "
                           "changed chunks - see the chunk list below, or drop --exact 0 "
                           "for exact versions and CVE matching")
        v["headline_zh"] = ("chunk 级模式（仅 manifest，未拉取 rpmdb）："
                            + (v.get("headline_zh") or "")
                            + f" ｜ {len(ld['changed_packages_from_chunks'])} 个软件包位于"
                              "发生变化的 chunk 中——见下方 chunk 列表；去掉 --exact 0 可获得精确版本与 CVE 匹配")
        return {"a": a, "b": b, "diff": diff, "layers": ld, "xc": xc, "verdict": v,
                "notes": notes + [T("manifest-only mode (--exact 0): no real versions or CVE matching",
                                    "仅 manifest 模式 (--exact 0)：无精确版本，也不做 CVE 匹配")]}
    cache_dir = args.cache_dir or os.path.expanduser("~/.cache/sbwatch")
    pa = load_pkglist(reg, a, ref_a, cache_dir, notes)
    pb = load_pkglist(reg, b, ref_b, cache_dir, notes)
    diff = pkg_diff(pa, pb)
    rel = fedora_release(pb)
    bodhi = None if args.no_bodhi else Bodhi(cache_dir=cache_dir, max_calls=args.max_bodhi)
    for c in diff["changed"]:
        c["cls"] = classify_change(c["old"], c["new"], rel, bodhi)
    xc = crosscheck_chunks(ld, diff, {n: p["src"] for n, p in pb.items()})
    backlog = []
    if getattr(args, "audit", False):
        ab = Bodhi(cache_dir=cache_dir, max_calls=max(args.max_bodhi, 45))
        backlog = security_backlog(pb, rel, ab, limit=max(args.max_bodhi, 45))
    bstate = {"failed": bodhi.failed, "skipped": bodhi.skipped} if bodhi else {"disabled": 1}
    v = verdict_of(diff, ld, meta, xc, backlog, bstate)
    if bstate.get("failed"):
        notes.append(T(f"WARNING: {bstate['failed']} Bodhi errata query(ies) failed; those "
                       f"packages were judged from changelog CVEs only",
                       f"警告：{bstate['failed']} 次 Bodhi 勘误查询失败；"
                       f"这些软件包仅依据更新日志中的 CVE 判断"))
    return {"a": a, "b": b, "diff": diff, "layers": ld, "xc": xc, "verdict": v,
            "notes": notes, "release": rel, "backlog": backlog}


def cmd_diff(args):
    res = do_diff(args, args.a, args.b)
    md = render_markdown(f"{args.image}: {shortref(args.a)} → {shortref(args.b)}",
                         res["a"], res["b"],
                         res["diff"], res["layers"], res["verdict"], res["notes"],
                         res.get("xc"), res.get("backlog"))
    if args.markdown:
        open(args.markdown, "w").write(md)
        log(T(f"wrote {args.markdown}", f"已写入 {args.markdown}"))
    else:
        print(md)
    if args.json_out:
        json.dump({"verdict": res["verdict"],
                   "download_bytes": res["layers"]["download_bytes"],
                   "changed": [{"name": c["name"], "old": c["old"]["evr"],
                                "new": c["new"]["evr"], "src": c["src"],
                                "dir": c["dir"],
                                "security": bool(c["cls"].get("security")),
                                "cves": c["cls"].get("cves", []),
                                "aliases": c["cls"].get("aliases", []),
                                "why": c["cls"].get("why", [])[:3]}
                               for c in res["diff"]["changed"]],
                   "silent_rebuilds": res.get("xc", {}).get("silent_rebuilds", []),
                   "behind_stable_security": res.get("backlog", []),
                   "added": res["diff"]["added"], "removed": res["diff"]["removed"]},
                  open(args.json_out, "w"), indent=1)
    return {"update-now": 2, "consider": 1, "skip": 0}.get(res["verdict"]["level"], 0)


def gh_outputs(pairs):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a") as f:
        for k, v in pairs.items():
            if isinstance(v, str) and "\n" in v:
                f.write(f"{k}<<EOF_SBWATCH\n{v}\nEOF_SBWATCH\n")
            else:
                f.write(f"{k}={v}\n")


def cmd_check(args):
    """Daily entry point: only do real work when the watched tag moved.

    The state file stores the *digest* we last analysed, so the next run diffs the
    new image against exactly the image you are (or were) running - and since the
    package list of that digest is already in the cache, a steady-state run only
    downloads one 33 MB chunk.
    """
    state_path = args.state or os.path.expanduser("~/.cache/sbwatch/state.json")
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    state = {}
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path))
        except Exception:
            state = {}
    reg = Registry(args.image, arch=args.arch)
    tks = [reg._token()]
    cur = resolve(reg, args.to, tks)
    maybe_verify_resolved(reg, cur, args)
    ver = cur["annotations"].get("org.opencontainers.image.version", "?")

    def save_state(extra=None):
        d = {"digest": cur["digest"], "index_digest": cur.get("index_digest"),
             "tag": args.to, "version": ver, "created": cur.get("created"),
             "inputhash": cur["annotations"].get("rpmostree.inputhash"),
             "checked": int(time.time())}
        if extra:
            d.update(extra)
        json.dump(d, open(state_path, "w"), indent=1)

    if state.get("digest") == cur["digest"] and not args.force:
        msg = T(f"no new build for {args.image}:{args.to} - still {ver} "
                f"({cur['digest'][:19]}...), nothing to download",
                f"{args.image}:{args.to} 无新构建——仍为 {ver}"
                f"（{cur['digest'][:19]}...），无需下载任何内容")
        log(msg)
        # silent exit: no report needed, but keep GITHUB_OUTPUT for the workflow
        # to skip notify/upload. Create a minimal report only if caller asked for one,
        # so that upload-artifact with if-no-files-found: warn doesn't warn.
        report = args.report or "report.md"
        try:
            # write a tiny placeholder if the workflow expects a file; otherwise skip
            if os.environ.get("GITHUB_ACTIONS"):
                with open(report, "w") as fh:
                    fh.write(f"# No new build 无新构建\n\n{msg}\n")
        except Exception:
            pass
        gh_outputs({"verdict": "no-update", "digest": cur["digest"], "summary": msg,
                    "download_bytes": 0, "report": report, "version": ver,
                    "inputhash": cur["annotations"].get("rpmostree.inputhash") or ""})
        return 0

    # what do we compare against? 1) explicit --a  2) last digest we analysed
    # 3) the most recent dated tag that is not the current image
    # recent builds, newest first: lets us (a) count the builds that landed since
    # the last look and (b) pick the immediate predecessor even on a multi-build day
    hist = []
    if args.scan:
        try:
            hist = build_history(reg, tks, scan=args.scan, days=0, to=args.to)
        except Exception as e:
            log(T(f"  ! history scan failed: {str(e)[:80]}",
                  f"  ！历史扫描失败：{str(e)[:80]}"))

    ref_a, label_a = args.a, args.a
    if not ref_a and state.get("digest") and state["digest"] != cur["digest"]:
        ref_a = state["digest"]
        label_a = str(state.get("version") or state.get("created") or state["digest"])[:26]
    if not ref_a and hist:
        for r in hist:
            if r["digest"] != cur["digest"] and (r.get("created") or "9") <= (cur.get("created") or "9"):
                ref_a = r["digest"]
                label_a = f"{r['version']} @ {str(r['created'])[:16]}"
                break
    if not ref_a:
        now = time.time()
        for i in range(1, 22):
            d = time.strftime("%Y%m%d", time.gmtime(now - i * 86400))
            dig = tag_exists(reg, d)
            if dig and dig != cur.get("index_digest"):
                ref_a, label_a = d, d
                break
    if not ref_a:
        msg = T(f"new build ({ver}) but no earlier image available to diff against",
                f"有新构建（{ver}），但没有可用于对比的更早镜像")
        log(msg)
        # first run / no baseline: don't fail the workflow, just report unknown
        # and let the workflow decide whether to notify. This used to return 1
        # which made the GitHub Action red.
        report = args.report or "report.md"
        try:
            if os.environ.get("GITHUB_ACTIONS"):
                with open(report, "w") as fh:
                    fh.write(f"# {msg}\n\nNo baseline image found to diff against / "
                             f"未找到可用于对比的基线镜像. "
                             f"Current 当前: {ver} {cur['digest'][:19]}...\n")
                json.dump({"verdict": {"level": "unknown"}, "version": ver,
                           "digest": cur["digest"]}, open(report + ".json", "w"), indent=1)
        except Exception:
            pass
        gh_outputs({"verdict": "unknown", "digest": cur["digest"], "summary": msg,
                    "download_bytes": 0, "report": report, "version": ver})
        save_state()
        return 0

    # rebuild-only fast path: if rpm-ostree's resolved inputs are byte-identical, no
    # package can have changed - skip the 33 MB rpmdb fetch entirely.
    if args.fast and not args.force:
        try:
            prev = resolve(reg, ref_a, tks, light=True)
            if (prev["annotations"].get("rpmostree.inputhash")
                    == cur["annotations"].get("rpmostree.inputhash")
                    and cur["annotations"].get("rpmostree.inputhash")):
                log(T("  identical inputhash -> manifest-only comparison (no rpmdb fetch)",
                      "  inputhash 相同 -> 仅用 manifest 对比（不拉取 rpmdb）"))
                args.exact = 0
        except Exception:
            pass

    res = do_diff(args, ref_a, args.to)
    v = res["verdict"]
    seen = state.get("created") or ""
    if seen:
        uniq, minutes = [], set()
        for r in sorted(hist, key=lambda x: x.get("created") or ""):
            k = (r.get("created") or "")[:16]
            if (r["digest"] in (cur["digest"], state.get("digest")) or not r["digest"]
                    or k in minutes or (r.get("created") or "") < seen):
                continue
            minutes.add(k)
            uniq.append(r)
        if uniq:
            res["notes"].append(
                f"this image is not the only new one: {len(uniq)} build(s) were pushed after "
                f"the build you last looked at ({seen[:16]}) — "
                + ", ".join(str(r["created"])[:16] for r in uniq)
                + " (UTC). Tags like `20260910` or `<sha>-44` are mutable and only point at "
                  "the newest build of a day, so the comparison below is by digest: your last "
                  "image -> current image, i.e. the full delta of skipping them all. / "
                f"这不是唯一的新镜像：在你上次查看的构建（{seen[:16]}）之后还推送了 {len(uniq)} 次构建 —— "
                + ", ".join(str(r["created"])[:16] for r in uniq)
                + " (UTC)。`20260910`、`<sha>-44` 之类的标签是可变的，只指向当天最新构建，"
                  "因此下方对比按 digest 进行：你的上一版镜像 -> 当前镜像，"
                  "即跳过它们全部时的完整差异。")
    md = render_markdown(
        f"secureblue update watch / secureblue 更新监控 - {args.image}  {shortref(label_a)} -> {args.to} ({ver})",
                         res["a"], res["b"], res["diff"], res["layers"], v, res["notes"],
                         res.get("xc"), res.get("backlog"))
    report = args.report or "report.md"
    with open(report, "w") as fh:
        fh.write(md)
    print(md)
    summary = (f"[{v['level'].upper()}] {v['headline']}"
               + (f" / {v['headline_zh']}" if v.get("headline_zh") else "")
               + f" | download 下载 {human(res['layers']['download_bytes'])}")
    print("\n" + "=" * 72, file=sys.stderr)
    print(summary, file=sys.stderr)
    json.dump({"verdict": v, "from": label_a, "to": args.to, "digest": cur["digest"],
               "version": ver, "download_bytes": res["layers"]["download_bytes"],
               "changed": [{"name": c["name"], "old": c["old"]["evr"], "new": c["new"]["evr"],
                            "src": c["src"], "dir": c["dir"],
                            "security": bool(c.get("cls", {}).get("security")),
                            "cves": c.get("cls", {}).get("cves", [])}
                           for c in res["diff"]["changed"]]},
              open(report + ".json", "w"), indent=1)
    save_state({"prev_digest": res["a"]["digest"], "prev_label": label_a,
                "last_verdict": v["level"]})
    gh_outputs({"verdict": v["level"], "digest": cur["digest"], "version": ver,
                "download_bytes": res["layers"]["download_bytes"], "summary": summary,
                "report": report, "cves": ",".join(v["cves"][:25]),
                "security_packages": ",".join(v["security_pkgs"][:25]),
                "changed_count": v["changed_pkg_count"]})
    if args.fail_on == "security" and v["level"] == "update-now":
        return 10
    return 0


# --------------------------------------------------------------------------- #
def add_common(p):
    p.add_argument("--image", default=DEFAULT_IMAGE,
                   help="registry repo (host/namespace/name) 镜像仓库（主机/命名空间/名称）, "
                        "default: %(default)s")
    p.add_argument("--arch", default="amd64", choices=["amd64", "arm64"])
    p.add_argument("--exact", type=int, default=1,
                   help="1 = read the rpmdb chunk for real NEVRAs + CVEs (~33 MB per image, "
                        "cached) / 读取 rpmdb chunk 获取精确 NEVRA 与 CVE（每镜像约 33 MB，带缓存）, "
                        "0 = manifest-only 仅用 manifest")
    p.add_argument("--no-bodhi", action="store_true",
                   help="do not query Fedora Bodhi (changelog-CVE matching only) / "
                        "不查询 Fedora Bodhi（仅按更新日志匹配 CVE）")
    p.add_argument("--max-bodhi", type=int, default=80,
                   help="cap on Bodhi API calls / Bodhi API 调用上限")
    p.add_argument("--audit", action="store_true",
                   help="also report published stable Fedora security updates the image is "
                        "missing (needs extra Bodhi calls) / 额外报告镜像缺少的已发布 stable "
                        "Fedora 安全更新（需要更多 Bodhi 调用）")
    p.add_argument("--cache-dir", default=None,
                   help="where to cache parsed package lists / Bodhi answers "
                        "(default ~/.cache/sbwatch) / 软件包列表与 Bodhi 应答的缓存目录"
                        "（默认 ~/.cache/sbwatch）")
    # optional cosign verification
    p.add_argument("--cosign-pub", default=None,
                   help="path to cosign public key to verify image signature "
                        "(e.g. https://github.com/secureblue/secureblue/raw/live/cosign.pub) / "
                        "用于校验镜像签名的 cosign 公钥路径")
    p.add_argument("--require-cosign", action="store_true",
                   help="fail if cosign verification fails or cosign binary missing / "
                        "cosign 校验失败或缺少 cosign 时直接失败退出")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sbwatch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("tags", help="show current image + recent dated tags / 显示当前镜像与近期日期标签")
    add_common(p)
    p.add_argument("--to", default="latest")
    p.add_argument("--days", type=int, default=21)
    p.set_defaults(func=cmd_tags)

    p = sub.add_parser("layers", help="chunk-level diff: what changed, what you'd download / "
                                      "chunk 级差异：变化内容与预计下载量")
    add_common(p)
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--json")
    p.set_defaults(func=cmd_layers)

    p = sub.add_parser("pkgs", help="exact package list (NEVRA) of one image / 单个镜像的精确软件包列表（NEVRA）")
    add_common(p)
    p.add_argument("ref")
    p.add_argument("--json", help="write machine-readable package list / 输出机器可读的软件包列表")
    p.set_defaults(func=cmd_pkgs)

    p = sub.add_parser("diff", help="exact package diff + security classification / 精确软件包差异 + 安全分类")
    add_common(p)
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--markdown")
    p.add_argument("--json-out")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("backlog", help="what security updates THIS image is still missing / 此镜像仍缺少哪些安全更新")
    add_common(p)
    p.add_argument("ref", nargs="?", default="latest")
    p.add_argument("--json-out")
    p.set_defaults(func=cmd_backlog)

    p = sub.add_parser("history", help="list recent builds (handles several per day) / 列出近期构建（支持一天多次）")
    add_common(p)
    p.add_argument("--to", default="latest")
    p.add_argument("--scan", type=int, default=12, help="how many builds to list / 列出多少次构建")
    p.add_argument("--days", type=int, default=7,
                   help="also resolve this many dated tags to label rows (0 = off) / "
                        "同时解析这么多天的日期标签来标注行（0 = 关闭）")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("check", help="stateful digest watch (for CI/cron) / 有状态 digest 监控（用于 CI/cron）")
    add_common(p)
    p.add_argument("--to", default="latest", help="tag to watch / 要监控的标签")
    p.add_argument("--a", default=None,
                   help="compare against this tag (default: state/recent tag) / 与该标签对比"
                        "（默认：状态文件/近期标签）")
    p.add_argument("--state", default=None, help="state json path / 状态 json 路径")
    p.add_argument("--report", default=None, help="markdown report path / Markdown 报告路径")
    p.add_argument("--force", action="store_true",
                   help="diff even if digest is unchanged / 即使 digest 未变也做对比")
    p.add_argument("--scan", type=int, default=12,
                   help="build refs to scan when searching for a baseline / newer builds "
                        "(0 = skip) / 搜索基线或新构建时扫描的构建数（0 = 跳过）")
    p.add_argument("--no-fast", dest="fast", action="store_false",
                   help="always do the exact rpmdb diff, even when inputhash is unchanged / "
                        "即使 inputhash 未变也始终执行精确 rpmdb 差异")
    p.set_defaults(fast=True)
    p.add_argument("--no-audit", dest="audit", action="store_false",
                   help="skip the 'behind on stable security updates' check / "
                        "跳过“落后于 stable 安全更新”的检查")
    p.set_defaults(audit=True)
    p.add_argument("--fail-on", choices=["nothing", "security"], default="nothing",
                   help="exit 10 when the report contains security fixes / "
                        "报告包含安全修复时以退出码 10 结束")
    p.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
