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
- secureblue 桌面会弹哪个通知——「重大漏洞已修复」/「漏洞已修复」/不弹？

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

## secureblue 通知预测

secureblue 更新后会弹通知，判定逻辑在一个 shell 脚本里
（`files/system/desktop/usr/libexec/secureblue/security-update-notification`），
它读 `rpm-ostree status --json` 的 `.cached-update`：

```
重大 (urgency=critical)：trivalent 在 .rpm-diff.upgraded 里  OR  最高勘误等级 == critical
普通 (urgency=normal)  ：kernel    在 .rpm-diff.upgraded 里  OR  最高勘误等级 ∈ {important, unknown}
否则：不弹任何通知
```

`sbwatch` 按同一条规则预测，结果放在 `verdict.secureblue_notification`（报告里是「secureblue notification 桌面通知预测」小节）：

```json
{
  "level": "major",
  "message": "A major security vulnerability has been patched",
  "max_advisory_severity": "unknown",
  "kernel_updated": true,
  "trivalent_updated": true,
  "security_advisory_count": 1,
  "why": ["trivalent upgraded ...", "kernel upgraded", "security advisory with rpm-ostree severity 'unknown'"]
}
```

`level` 取值 `major` / `normal` / `none`，以及 `unknown`（`--exact 0` 未读版本时）。

### 两个容易搞错的细节

**1. Fedora 根本不发布 severity，所以「重大」只由 trivalent 触发。**
`max_advisory_severity` 来自 rpm-ostree 的 `str2severity()`，它只认 RHEL 拼写
`LOW/MODERATE/IMPORTANT/CRITICAL`，其它一律返回 `NONE(0)`；而 secureblue 的 `case`
没有 `0` 的分支，0 落进 `*)` 变成 `unknown`。实测 Fedora 官方镜像的
updateinfo.xml：F44 的 2979 条 `<update>` 标签中**带 `severity=` 属性的是 0 条**
（只有 `from/status/type/version`），Bodhi 自己的枚举又是
`unspecified/urgent/high/medium/low`——没有 `critical`。所以：

- `critical` 在 Fedora 上**不可达**
- 任何 security 勘误都落到 `unknown` → **普通**通知
- `low`/`moderate` 单独出现时**不弹通知**（除非同时动了 kernel/trivalent）

**2. trivalent 必须硬编码，靠 CVE 匹配永远抓不到它。**
trivalent 是 secureblue 自己的包、无 dist tag，**结构上不可能匹配到任何 Bodhi 勘误**。
而上游把**任何** trivalent 升级都判为重大通知（secureblue FAQ：Trivalent 是在上游
Chromium CVE 修复后才推的）。因此 `sbwatch` 直接按包名判断，不依赖勘误。

> 预测为 `major` 时，verdict 会被强制抬到 `update-now`——厂商用 critical 紧急度 +
> Reboot 动作提示的东西，不该停留在 `consider`。

## 关于 `rpmostree.inputhash`（重要）

**它不是这次构建的哈希，而是从 Fedora 基础镜像继承来的，描述的是 Fedora 自己的 compose。**

- 该值由 `rpm-ostree compose tree` 计算（= SHA256(treefile 校验和 + dnf 事务 goal
  的 repodata 校验和)），写进 ostree commit 元数据，导出 OCI 时被拷进 config labels。
- blue-build **从不运行** `compose tree`——它唯一的 compose 调用是重分块器
  `rpm-ostree compose build-chunked-oci`。所以 secureblue 原样继承这个值。
- 实测：两个不同的 secureblue 镜像（128 层中有 20 层不同、
  `homebrew 7.0.2-26091605 → 7.0.6-26092310`）共享**完全相同**的
  `rpmostree.inputhash`、`ostree.commit`、`ostree.linux`、`ostree.final-diffid`；
  且每个镜像的这些值都等于**它自己 base 镜像**的值。

**结论：`inputhash` 相同不能证明软件包没变。** 同理 `ostree.commit` 也不能。
判断有没有变化，必须看包表（rpmdb）或 rpmdb chunk 的 digest。
报告与 `history` 里凡出现该值相同的地方，都会附上这条说明。

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

# 3. 只看 manifest，不拉 rpmdb (秒级，约 50KB 而不是 33MB)
python3 sbwatch.py diff 20260916 latest --exact 0
#    manifest-only 模式：只对比 OCI manifest 的层清单与 chunkah 注解。
#    能得到：下载量、chunk 复用率、哪些【包名】落在变化的 chunk 里。
#    得不到：任何版本号 —— 因此没有包 diff、不做 CVE/勘误匹配、
#            无法判断 kernel/trivalent 是否升级，通知预测只能给 unknown。
#    实测同一对镜像：--exact 0 说"241 个包位于变化的 chunk 中"，
#    --exact 1 才知道真正变的只有 8 个。报告里会明确声明未读版本。

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
| `update-now` | 含 CVE / security erratum，或 critical/high severity，**或 secureblue 会弹重大通知** | 立刻 `rpm-ostree upgrade && systemctl reboot` |
| `consider` | kernel 变了 / 安全敏感包 bump / silent rebuild 含重要包 | 看下载量决定 |
| `skip` | 常规 churn，无 CVE，无 security erratum | 可跳过 |
| `no-change` | **rpmdb 里没有任何软件包发生变化**（且确实读过版本），chunk 只是重发 | 跳过，更新无意义 |
| `no-update` | registry digest 未变 | 无新构建 |

> `no-change` 的判据是**包集合为空**，不是 `rpmostree.inputhash` 相同——后者继承自
> Fedora base，相同也不能证明没变化（见上文）。`--exact 0` 未读版本时同样不会给出
> `no-change`，因为那时"没有包变化"无从证实。


报告里会包含：
- 下载量：`download_bytes / total_size_b / download_pct`
- `secureblue_notification`：桌面会弹哪个通知 + 触发原因（见上文）
- `silent_rebuilds`：版本没变但 chunk 变了（工具链/macro/文件重排）
- `downgrades` / `cves_dropped`：这次更新回退了已发布修复
- `backlog`：即使跳过，你仍暴露在多少已发布 stable 安全更新之外
- `same_inputhash_but_packages_moved`：inputhash 相同但包确实动了（显式告警，别拿 inputhash 当无变化的证据）

### `check --fast` 与 manifest-only

`check` 默认带 `--fast`：当**两个镜像的 rpmdb chunk digest 相同**时，跳过 33MB 拉取、
自动降级为 manifest-only。这是安全的——rpmdb.sqlite 逐字节相同 ⟹ 包集合必然没变。

> 早期版本用 `rpmostree.inputhash` 相同作为跳过依据，那是错的（见上文）。实测最近
> 8 次构建的 7 对相邻组合：旧条件会跳过 **5 次**，而那 5 次的 rpmdb **全都不同**
> （含 kernel 7.2.6→7.2.7 + trivalent 153→154 那次）；新条件跳过 **0 次**。
> 代价是那 33MB 的节流在 secureblue 上基本不再触发——它几乎每次都重建了某个东西。
> 想强制精确对比加 `--no-fast`（或 workflow_dispatch 勾选 `force`）。


### 退出码

所有子命令**正常运行一律以 0 退出**，无论 verdict 是什么（verdict 从报告、
stdout 或 `--json-out` 的 `verdict.level` 读取）；非零退出码只表示运行出错
（网络/registry/参数错误等）。唯一的显式例外是 `check --fail-on security`：
发现安全修复时以 **10** 退出，专供 CI 使用（本仓库 workflow 的
`FAIL_ON_SECURITY` 变量即依赖它）。

## 测试

`tests/test_sbwatch.py` 是 **80 项离线回归测试**，不需要网络、不访问 registry
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
| **F** | **secureblue 通知规则**：Bodhi 的 `urgent/high/medium` 在 rpm-ostree 词表下一律为 0（不得预测出桌面不会显示的紧急度）；Fedora 无 severity ⟹ 必须落 `unknown` 而非 `none`；trivalent 单独升级 ⟹ `major` 且把 verdict 抬到 `update-now`；kernel 靠**包 diff** 识别（`ostree.linux` 相同也要认出来）；kernel 降级不算升级；11 行真值表与上游 `case` 逐条对拍；仅匹配旧构建或未推送的勘误不得触发 |
| **G** | **`no-change` 的判据**：inputhash 相同但包动了 ⟹ 不得判 `no-change`；`--exact 0` 未读版本 ⟹ 也不得判 `no-change`、不得声称"rpmdb 中无变化"；措辞不得再出现"逐字节一致"；`rpmdb_chunk()` 的选层规则必须与 `package_list()` 一致（否则快速路径会校验 A 层却读 B 层） |
| **H** | **报告独立双语排版与决策修正**：报告输出格式改为纯中文在上、`---` 分割、纯英文在下；trivalent 将判定从 `consider` 提升至 `update-now` 时剥离冲突的“可合理跳过”文案；`check --fast` 命中相同 rpmdb chunk 时保留无变更确证，正确输出 `no-change` |

其中 A6 的向量取自 rpm 上游 `tests/rpmvercmp.at`，已抓取为
`tests/rpmvercmp_vectors.json`，因此**离线也能验证**与 rpm 本体的一致性。

CI 中由 `test` 作业运行；`watch` 作业**不**依赖 `test`（两者并行）——测试失败
不会阻塞每小时的监控，但会在 Tests 作业中红牌示警。

## GitHub Action

仓库自带 `.github/workflows/sbwatch.yml`，每小时跑一次：

- cache `~/.cache/sbwatch` (pkglist + Bodhi + state.json)，按 image+arch 分命名空间，
  并有一个 prune 步骤只保留最近 7 份（否则 `state.json` 会被 LRU 挤掉，`check` 就失去基线）
- `sbwatch.py check` → `report.md` + `report.md.json` → summary + artifact
  （workflow 不传 `--exact` / `--no-fast`，所以走默认值：`--exact 1` + `--fast` 开启，
  见上文「`check --fast` 与 manifest-only」）
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
