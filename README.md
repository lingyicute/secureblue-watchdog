# secureblue-watchdog

[![Update Watch](https://github.com/lingyicute/secureblue-watchdog/actions/workflows/sbwatch.yml/badge.svg)](https://github.com/lingyicute/secureblue-watchdog/actions/workflows/sbwatch.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

**Know what a secureblue update actually changes, *before* you download it.**

secureblue (基于 Fedora Atomic / Universal Blue) 的完整镜像 ~4GB，每次 `rpm-ostree upgrade` 都要盲下。`sbwatch` 利用 `chunkah` 重分块构建的特性，只拉取 manifest (~50KB) 和 `rpmdb.sqlite` 层 (~33MB)，就能告诉你：

- 这次更新要下载多少？多少 chunk 可重用？
- 精确的包版本 diff (NEVRA)？
- 是否包含 CVE 修复？严重等级？
- 是静默重建还是真有变化？

## 原理

secureblue 镜像由 blue-build + `chunkah` 构建，每层都有注解：

```json
"annotations": {
  "org.chunkah.component": "rpm/kernel rpm/curl",
  "org.chunkah.stability": "0.006"
}
```

1. **manifest 是包→chunk 的映射**：对比两个 manifest 就知道哪些包内容变了，哪些 chunk 要重下 → 真实下载量。
2. **RPM 数据库是独立 chunk** (`bigfiles/rpmdb.sqlite`)：只拉这一个 blob (~33MB 代替 ~4GB) 就能拿到 2200+ 包的精确 NEVRA + changelog (Fedora 会在 changelog 写 `Fix CVE-YYYY-NNNNN`)，结合 Fedora Bodhi API 就能做安全分类。

## 安装

```bash
git clone https://github.com/lingyicute/secureblue-watchdog
cd secureblue-watchdog
# 可选：下载 secureblue 官方 cosign 公钥用于签名校验
curl -O https://raw.githubusercontent.com/secureblue/secureblue/live/cosign.pub
python3 sbwatch.py --help
```

依赖：Python 3.10+，仅标准库。`cosign` 二进制可选，用于 `--cosign-pub` 校验。

## CLI

```bash
sbwatch tags                  # 当前镜像 + 近期 dated tag
sbwatch history               # 列出最近 N 次真实构建 (通过 sig 标签发现，处理一天多推)
sbwatch layers A B            # chunk 级别 diff + 预估下载大小
sbwatch pkgs A                # 某个镜像的精确包列表
sbwatch diff A B              # 精确包 diff + CVE 分类
sbwatch backlog [ref]         # 这个镜像还缺哪些已发布的 stable 安全更新
sbwatch check                 # 有状态的 digest watch，用于 CI/cron -> report.md + verdict + $GITHUB_OUTPUT

# A/B/ref 可以是：
#   latest | 44 | 20260916 | 9ec80ca-44 | sha256:<digest>
# 推荐用 digest，因为 dated tag 是可变的
#
# ⚠️ `diff A B` / `layers A B` 中的 A 必须是【较旧】的一方，B 是【较新】的一方。
#    写反了会得出完全相反的结论（把新镜像里新增的 CVE 说成"本次更新移除的修复"）。
#    工具现在会用 `org.opencontainers.image.created` 自动纠正顺序并在报告里说明；
#    如需强制保持你给的顺序，加 --keep-order。
# 先用 `sbwatch.py history` 或 `sbwatch.py tags` 确认哪个 tag 更新。
```

### 示例

```bash
# 1. 看当前 latest 和更早的 dated tag 之间的 chunk 变化（旧 -> 新）
python3 sbwatch.py layers 20260916 latest --image secureblue/silverblue-main-hardened

# 2. 精确 diff，带 CVE 判定（旧 -> 新）
python3 sbwatch.py diff 20260916 latest --markdown diff.md --json-out diff.json

# 3. 只看 manifest，不拉 rpmdb (秒级)
#    注意：这个模式没有读取任何软件包版本，所以它不会断言"哪些包版本没变"，
#    也不做 CVE 匹配——报告里会明确写出这一点。
python3 sbwatch.py diff 20260916 latest --exact 0

# 4. 带签名校验 (P0 加固)；校验结果会写进报告
python3 sbwatch.py diff 20260916 latest --cosign-pub ./cosign.pub --require-cosign

# 5. CI 模式：只有 tag 移动时才做重活
python3 sbwatch.py check --image secureblue/silverblue-main-hardened --to latest --report report.md

# 6. 看这个镜像还落后多少安全更新
python3 sbwatch.py backlog latest --max-bodhi 80
```

### Verdict 解释

| level | 含义 | 建议 |
|-------|------|------|
| `update-now` | 含 CVE / security erratum，或 critical/high severity | 立刻 `rpm-ostree upgrade && systemctl reboot` |
| `consider` | kernel 变了 / 安全敏感包 bump / silent rebuild 含重要包 | 看下载量决定 |
| `skip` | 常规 churn，无 CVE，无 security erratum | 可跳过 |
| `no-change` | `rpmostree.inputhash` 完全相同，chunk 只是重发 | 跳过，更新无意义 |
| `no-update` | registry digest 未变 | 无新构建 |

报告里会包含：
- 下载量：`download_bytes / total_size_b / download_pct`
- `silent_rebuilds`：版本没变但 chunk 变了（工具链/macro/文件重排）
- `downgrades` / `cves_dropped`：这次更新回退了已发布修复
- `backlog`：即使跳过，你仍暴露在多少已发布 stable 安全更新之外

## 测试

`tests/test_sbwatch.py` 是 **56 项离线回归测试**，不需要网络、不访问 registry
或 Bodhi，也不依赖 `rpm` 二进制或 python `rpm` 模块：

```bash
python3 -m unittest discover -s tests      # 或 python3 tests/test_sbwatch.py
```

覆盖的行为（每组都对应一个曾经真实出错的判定）：

| 组 | 锁住的行为 |
|---|---|
| A1 / A3 | 匹配**旧版本**的勘误、以及 `status != stable` 的勘误，都不得抬高结论 |
| A2 | `build_history` 的行必须同时带 index digest 与 platform digest，两者不可互换（`list_tags` 已打桩，套件零网络访问） |
| A4 | 未读取软件包版本时，不得断言"版本相同但被重建" |
| A5 | `A B` 中 A 必须是较旧的一方，否则自动纠正 |
| A6 | `rpmvercmp` 与 rpm 上游 **91 条**测试向量逐条一致（含 `^`、数字段胜过字母段、`~`） |
| A7 | Bodhi 匹配必须同时提供**源码包拼写**（shim-x64 → `shim-16.1-5` 等 246/1107 个无同名二进制的源码包）与剥离 `.secureblue.N` 后的拼写 |
| B1 | Bodhi 缓存损坏/形状不符时丢弃重取；CVE 可从 `bugs[].title` 提取 |
| — | Bodhi 分页：超过一页的勘误必须全部读到，读到上限时要报告"审计不完整" |
| C1 | backlog 审计的覆盖率必须可见（候选/已查/被截断/池内缺失）；池条目必须是真实源码包名 |
| C2 | backlog 匹配：epoch>0 的包（cups、bind、grub2…）不得因 Bodhi NVR 无 epoch 而永远"不落后"；`.secureblue.N` 标记不得抬高本地 release |
| D | 已删除的死代码不得复活（含 `Bodhi._read_cache`、`Registry.__enter__/__exit__`）；`RPMTAG[1006]` 不得再被当作 `buildhost` |
| E3 / E5 | 状态原子写入；`fedora_release` 由数据推导而非硬编码 |
| E6 | `pkg_diff`：仅 epoch 变化（0:1.2-3 → 1:1.2-3）必须可见 |
| E7 | `pick_tar_member`：活镜像 tar 内有两个 `rpmdb.sqlite`（92MiB 真库 + 0 字节占位），必须按大小选、与 tar 顺序无关 |

其中 A6 的向量取自 rpm 上游 `tests/rpmvercmp.at`，已抓取为
`tests/rpmvercmp_vectors.json`，因此**离线也能验证**与 rpm 本体的一致性。

CI 中由 `test` 作业运行；`watch` 作业**不**依赖 `test`（两者并行）——测试失败
不会阻塞每小时的监控，但会在 Tests 作业中红牌示警。

### 退出码

所有子命令**正常运行一律以 0 退出**，无论 verdict 是什么（verdict 从报告、
stdout 或 `--json-out` 的 `verdict.level` 读取）；非零退出码只表示运行出错
（网络/registry/参数错误等）。唯一的显式例外是 `check --fail-on security`：
发现安全修复时以 **10** 退出，专供 CI 使用（本仓库 workflow 的
`FAIL_ON_SECURITY` 变量即依赖它）。

## GitHub Action

仓库自带 `.github/workflows/sbwatch.yml`，每小时跑一次：

- cache `~/.cache/sbwatch` (pkglist + Bodhi + state.json)，按 image+arch 分命名空间，
  并有一个 prune 步骤只保留最近 7 份（否则 `state.json` 会被 LRU 挤掉，`check` 就失去基线）
- `sbwatch.py check` → `report.md` + `report.md.json` → summary + artifact
- 若 verdict 不是 `no-update`/`no-change`/`unknown`，会评论到 sticky issue
  `secureblue update watch`
- 若配置了 `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` secrets，推送到 Telegram

环境变量（workflow_dispatch 输入）：
- `SB_IMAGE` (默认 `secureblue/silverblue-main-hardened`)
- `SB_ARCH` (`amd64`/`arm64`)
- `SB_FROM` (与指定 tag 对比，而不是上次看到的镜像)

仓库变量（Settings → Secrets and variables → Actions → **Variables**，不是 Secrets）：
- `POST_SKIP_VERDICT` (默认 `false`，`true` 时 skip 也通知)
- `FAIL_ON_SECURITY` (默认 `false`，`true` 时会给 sbwatch 传 `--fail-on security`，
  安全更新会让 run 变红)

## 🗂️ License

This program is released under the GNU Affero General Public License v3.0 (AGPLv3).

Copyright (C) 2026 lingyicute.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see https://www.gnu.org/licenses.
