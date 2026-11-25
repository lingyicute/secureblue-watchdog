# secureblue-watchdog

[![Update Watch](https://github.com/lingyicute/secureblue-watchdog/actions/workflows/sbwatch.yml/badge.svg)](https://github.com/lingyicute/secureblue-watchdog/actions/workflows/sbwatch.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

**Know what a secureblue update actually changes, *before* you download it.**

`secureblue`（基于 Fedora Atomic / Universal Blue 构建的硬化桌面系统）的完整 OCI 镜像体积约 **4 GB**。日常执行 `rpm-ostree upgrade` 时，系统往往要先把几百 MB 甚至上 GB 的数据拉下来，你才能知道这次更新究竟改了什么。

`sbwatch` 利用 `secureblue` 镜像采用 `blue-build` + `chunkah` 重分块（rechunking）构建的特性，**无需 `podman`、无需 `root` 权限、无需登录 Registry、无需本机安装 `rpm` 命令或任何第三方 Python 库**（纯 Python 标准库实现），只需拉取约 **50 KB 的 OCI Manifest** 和约 **33 MB 的 `rpmdb.sqlite` 数据库层**，就能在几秒内告诉你：

1. **真实下载体积**：这次更新要下载多少数据？有多少个分块（chunk）可以直接复用本地已有层？
2. **精确包版本差异（NEVRA）**：镜像内 2200+ 个软件包中，具体哪些包发生了升级、降级、架构变更、新增或移除？
3. **安全与 CVE 判定**：本次更新是否包含 CVE 修复或 Fedora 安全勘误（Errata）？严重等级（Critical / Important / Moderate / Low）是什么？是否因回滚而倒退了安全修复？
4. **静默变化识别**：是真正的软件包版本升级，还是软件包版本未变但压缩层内容变了（如构建时生成的缓存文件变化），抑或是非软件包文件（如 `initramfs`、`secureblue` 自身配置）发生了改动？
5. **桌面通知预测**：更新后 `secureblue` 桌面会弹出哪条通知——「重大漏洞已修复（MAJOR）」/「漏洞已修复（normal）」/ 不弹窗？在**默认安装**与**叠加了软件包（layered packages）**的系统上表现有何不同？
6. **安全更新积压审计（Backlog）**：当前镜像相比 Fedora 官方已经推送至 `stable` 仓库的安全更新，还落后哪些修复？

---

## 目录

- [核心原理](#核心原理)
  - [1. Manifest 是「组件 → 分块（chunk）」的映射表](#1-manifest-是组件--分块chunk的映射表)
  - [2. RPM 数据库位于独立的 `rpmdb.sqlite` 分块](#2-rpm-数据库位于独立的-rpmdbsqlite-分块)
  - [3. 重要陷阱：为什么不能相信 `rpmostree.inputhash`？](#3-重要陷阱为什么不能相信-rpmostreeinputhash)
- [快速开始与安装](#快速开始与安装)
- [CLI 命令指南](#cli-命令指南)
  - [子命令一览](#子命令一览)
  - [镜像引用格式与新旧顺序说明](#镜像引用格式与新旧顺序说明)
  - [公共参数](#公共参数)
  - [子命令专属参数](#子命令专属参数)
  - [常用示例](#常用示例)
- [升级建议（Verdict）与安全判定规则](#升级建议verdict与安全判定规则)
  - [六种结论级别](#六种结论级别)
  - [安全证据来源细分（`security_basis`）](#安全证据来源细分security_basis)
  - [降级（回滚）与“不再提及的 CVE”处理](#降级回滚与不再提及的-cve处理)
- [secureblue 桌面通知预测](#secureblue-桌面通知预测)
  - [上游弹窗判定规则](#上游弹窗判定规则)
  - [三个关键实现细节](#三个关键实现细节)
  - [通知预测 JSON 结构](#通知预测-json-结构)
- [进阶机制与报告约定](#进阶机制与报告约定)
  - [`--exact 0`（仅 Manifest 模式）与 `check --fast`](#--exact-0仅-manifest-模式与-check---fast)
  - [Cosign 签名校验与端到端完整性保护](#cosign-签名校验与端到端完整性保护)
  - [Bodhi 调用预算、缓存与断点续查](#bodhi-调用预算缓存与断点续查)
  - [拒绝静默截断（Truncation Disclosure）与双语排版](#拒绝静默截断truncation-disclosure与双语排版)
  - [JSON 输出结构与摘要标识说明](#json-输出结构与摘要标识说明)
  - [退出码约定](#退出码约定)
- [GitHub Actions 自动化监控](#github-actions-自动化监控)
  - [工作流特性](#工作流特性)
  - [配置项（输入参数、Variables 与 Secrets）](#配置项输入参数variables-与-secrets)
- [安全加固与离线回归测试](#安全加固与离线回归测试)
- [许可](#许可)

---

## 核心原理

### 1. Manifest 是「组件 → 分块（chunk）」的映射表

`secureblue` 镜像由 `blue-build` 配合 `chunkah` 构建，OCI Manifest 中的每一个层（layer）都带有组件与稳定性注解：

```json
"annotations": {
  "org.chunkah.component": "rpm/kernel rpm/curl",
  "org.chunkah.stability": "0.006"
}
```

- **下载量估算**：对比两个镜像的 Manifest，按压缩层摘要（`sha256` digest）计算集合差，即可得出需要重新下载的唯一压缩层总字节数（`download_bytes`）。
  - *注：该下载量是一个**上限值**——它统计了所有摘要发生变化的层，而 `chunkah` 在不同构建间可能会将部分已有文件重新切分到不同组件层中。*
- **层布局变化披露**：OCI 镜像按顺序叠加各层，因此**删除旧层、调整复用层的排列顺序或改变重复引用次数**，即使不增加任何下载流量，也可能改变最终的文件系统结果。`sbwatch` 会在 `layers` 与 diff JSON 中分别记录 `chunks_removed`（不再引用的旧层数）与 `reused_layer_sequence_changed`（复用层顺序或重复次数是否改变），并在报告中加以说明。

### 2. RPM 数据库位于独立的 `rpmdb.sqlite` 分块

整个系统的 RPM 数据库被单独打包在名为 `bigfiles/rpmdb.sqlite` 的层中（压缩后约 33 MB，解压后约 92 MB）：

- 只需流式下载这一个层，并用 Python 内置的 `sqlite3` 模块解析其中的 `Packages` 表，就能直接读取全部 2200+ 个软件包的二进制 RPM Header（兼容传统 RPM 魔数头部与 RPM 4.16+ NDB 格式）。
- 从包头中可精确提取每个包的 `Name`、`Epoch`、`Version`、`Release`、`Arch`（合称 **NEVRA**）、源码包信息（`Sourcerpm`）、构建商（`Vendor`）以及完整的 **RPM 更新日志（Changelog）**。
- Fedora 维护者会在更新日志中记录形如 `Fix CVE-YYYY-NNNNN` 的信息；结合 **Fedora Bodhi API** 的已发布勘误数据，即可完成高精度的安全分类。

### 3. 重要陷阱：为什么不能相信 `rpmostree.inputhash`？

在分析 `secureblue` 镜像时，**绝不能用 `rpmostree.inputhash`（或 `ostree.commit`、`ostree.linux`、`ostree.final-diffid`）相同来推断“软件包没有变化”**。

- **产生机制**：`rpmostree.inputhash` 是由 `rpm-ostree compose tree` 计算的（等于 `SHA256(treefile 校验和 + dnf 事务目标 repodata 校验和)`），写入 ostree commit 元数据后，在导出 OCI 镜像时被拷贝到镜像的 config labels 中。
- **继承盲区**：`blue-build` 在构建 `secureblue` 时**从不运行 `compose tree`**——它唯一调用的 compose 子命令是重分块器 `rpm-ostree compose build-chunked-oci`。因此，`secureblue` 镜像原封不动地从上游 Fedora 基础镜像继承了这些标签值。
- **实测反例**：同一天构建的两个不同 `secureblue` 镜像（128 个层中有 20 个层不同，且包含 `homebrew 7.0.2 → 7.0.6` 或 `secureblue` 自建内核与 `trivalent` 的升级）拥有**完全相同**的 `rpmostree.inputhash`、`ostree.commit` 和 `ostree.linux`，且均等于它们各自上游 Fedora base 镜像的值。

**结论**：
1. 判断软件包是否变化，必须对比实际的 RPM 包表（`rpmdb.sqlite`）或确认两个镜像的 `rpmdb.sqlite` 层摘要完全一致。
2. 判断内核是否升级，必须看 `rpmdb` 中实际安装的 `kernel` 软件包版本，而不能只看继承自 Fedora 基础镜像的 `ostree.linux` 注解（报告的元数据表会同时列出这两项以便核对）。
3. 当两个镜像的 `inputhash` 相同但软件包实际发生变动时，`sbwatch` 会将 `verdict.same_inputhash_but_packages_moved` 设为 `true`，并在报告中显式发出告警。

---

## 快速开始与安装

```bash
git clone https://github.com/lingyicute/secureblue-watchdog
cd secureblue-watchdog

# 查看帮助信息
python3 sbwatch.py --help
```

- **运行环境**：Python 3.10+，**仅使用 Python 标准库**，无需 `pip install` 任何依赖。
- **签名校验（可选）**：如需校验镜像签名，请在系统中安装 [`cosign`](https://github.com/sigstore/cosign) 二进制程序。仓库已自带经校验的 `secureblue` 官方公钥 `cosign.pub`（其 SHA256 已固定在工作流的 `COSIGN_PUB_SHA256` 中），直接使用 `--cosign-pub ./cosign.pub` 即可，无需从网络重新下载覆盖。

---

## CLI 命令指南

### 子命令一览

```bash
python3 sbwatch.py tags                  # 查看当前镜像摘要、元数据 + 近期按日期命名的标签
python3 sbwatch.py history               # 列出最近 N 次真实构建（通过 .sig 签名标签发现，支持一天多次推送）
python3 sbwatch.py layers A B            # 仅对比 Manifest：查看分块级差异与预计下载体积
python3 sbwatch.py pkgs [ref]            # 提取并列出单个镜像的精确软件包表（NEVRA）
python3 sbwatch.py diff A B              # 精确包级 diff + CVE/勘误安全分类 + 桌面通知预测
python3 sbwatch.py backlog [ref]         # 审计该镜像相比 Fedora 已发布的 stable 安全更新还落后哪些包
python3 sbwatch.py check                 # 有状态的 digest 监控（供 CI/cron 使用）-> 生成报告、JSON 与 $GITHUB_OUTPUT
```

### 镜像引用格式与新旧顺序说明

- **支持的引用（`A` / `B` / `ref`）格式**：
  - 分支/浮动标签：`latest`、`44`
  - 日期标签：`20260916`、`20260916-44`
  - 提交短哈希标签：`9ec80ca-44`
  - 不可变摘要（**推荐**）：`sha256:<64位十六进制>`
  - *提示*：所有命名标签（包括日期标签 `20260916`）都是可变指针——同一天内多次构建共用同一个版本号，且日期标签只会指向当天最新一次推送。若要精确定位某次特定构建，请先运行 `sbwatch.py history` 获取其不可变的 `sha256` digest。
  - 若在 `--image` 中直接附带了标签（如 `--image secureblue/silverblue-main-hardened:44`），该标签会自动作为 `--to` 或 `ref` 的默认值（显式传入的 `--to` 或 `ref` 参数优先级更高）。

- **关于 `A B` 的新旧顺序（重要）**：
  - 在 `diff A B` 与 `layers A B` 中，**`A` 代表较旧的一方（基线），`B` 代表较新的一方（目标）**。
  - 如果把新旧顺序写反，结论会完全颠倒（例如把新镜像刚刚修复的 CVE 当成“新版更新日志不再提及的 CVE”）。
  - 为防止误操作，`sbwatch` 默认会根据镜像的 `org.opencontainers.image.created` 构建时间**自动将较旧的镜像调整为 `A`**，并在报告开头注明已自动交换顺序；如果你确实希望强制按手动给定的顺序对比（例如专门分析一次回滚），请加上 `--keep-order`。

### 公共参数

所有子命令均支持以下公共参数：

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--image REPO` | `secureblue/silverblue-main-hardened` | 镜像仓库路径（支持 `[host/]namespace/name[:tag][@sha256:...]`，省略主机名时默认为 `ghcr.io`） |
| `--arch {amd64,arm64}` | `amd64` | 目标平台架构 |
| `--exact {0,1}` | `1` | `1` = 拉取并解析 `rpmdb.sqlite` 获取精确版本与 CVE（带缓存）；`0` = 仅分析 Manifest |
| `--keep-order` | 关闭 | 不按构建时间自动交换 `A` 和 `B`，严格以传入顺序将 `A` 视为旧镜像、`B` 视为新镜像 |
| `--no-bodhi` | 关闭 | 禁用 Fedora Bodhi API 查询（仅依赖 RPM 更新日志识别 CVE；不可与 `backlog` 同用） |
| `--max-bodhi N` | `100` | 单次运行允许发起的 Bodhi API HTTP 请求次数上限（非负数） |
| `--bodhi-seconds SEC` | `0`（不限） | 启动新 Bodhi 请求的总耗时预算（秒），超时后不再发起新请求（已缓存数据仍正常读取） |
| `--audit` | `check` 默认开启，其余关闭 | 在对比同时审计目标镜像仍缺少哪些已发布的 Fedora `stable` 安全更新 |
| `--backlog-candidates N` | 不限（全部候选） | 限制 `backlog` 或 `--audit` 最多检查候选池中的多少个源码包（仍受 `--max-bodhi` 总预算约束） |
| `--cache-dir DIR` | `~/.cache/sbwatch` | 软件包表与 Bodhi 响应的本地缓存目录 |
| `--cosign-pub PATH` | 无 | 用于校验镜像签名的 cosign 公钥文件路径（如 `./cosign.pub`） |
| `--require-cosign` | 关闭 | 强制要求签名校验通过（必须同时指定 `--cosign-pub`；若缺少 `cosign` 命令、公钥不存在或校验失败则直接报错退出） |

### 子命令专属参数

| 子命令 | 参数 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `tags` | `--to TAG` | `latest`（或 `--image` 中的标签） | 要查看的目标标签 |
| | `--days N` | `21` | 向前探测最近多少天的日期标签（如 `20260916`） |
| `history` | `--to TAG` | `latest`（或 `--image` 中的标签） | 历史回溯的锚点标签 |
| | `--scan N` | `12` | 列出最近多少次真实构建（正整数） |
| | `--days N` | `7` | 解析最近多少天的日期标签以标注对应的构建行（`0` 为关闭） |
| | `--at-digest DIGEST` | 无 | 使用已解析的顶层 `sha256:<64 hex>` 摘要固定历史起点，避免运行期间标签移动 |
| `layers` | `a` `b` | （必填） | 要对比的两个镜像引用（旧 → 新） |
| | `--json PATH` | 无 | 将分块差异结果输出为 JSON 文件（传入 `-` 或 `/dev/stdout` 可直接输出到标准输出） |
| `pkgs` | `[ref]` | `latest`（或 `--image` 中的标签） | 要导出软件包列表的镜像引用 |
| | `--json PATH` | 无 | 将包表（不含冗长更新日志原文）与完整性统计输出为 JSON（支持 `-` 输出到标准输出） |
| `diff` | `a` `b` | （必填） | 要对比的两个镜像引用（旧 → 新） |
| | `--markdown PATH` | 无 | 将中英双语 Markdown 报告写入指定文件（未指定且未将 JSON 定向到标准输出时打印到终端） |
| | `--json-out PATH` | 无 | 将完整结构化对比结果写入 JSON 文件（支持 `-` 输出到标准输出） |
| `backlog` | `[ref]` | `latest`（或 `--image` 中的标签） | 要审计积压安全更新的镜像引用 |
| | `--json-out PATH` | 无 | 将积压审计结果与覆盖率写入 JSON 文件（支持 `-` 输出到标准输出） |
| `check` | `--to TAG` | `latest`（或 `--image` 中的标签） | 要持续监控的目标标签 |
| | `--a REF` | 自动选择 | 显式指定对比基线（指定后即使目标标签 digest 未变也会执行对比） |
| | `--state PATH` | `~/.cache/sbwatch/state.json` | 记录上次已分析镜像状态的文件路径 |
| | `--report PATH` | `report.md` | 输出 Markdown 报告的路径（同时自动生成同名的 `<report>.json`） |
| | `--force` | 关闭 | 即使目标标签 digest 与上次相同，也强制重新对比 |
| | `--scan N` | `12` | 当缺少可用状态基线或统计中间跳过构建数时，扫描构建历史的条数（`0` 为跳过） |
| | `--no-fast` | 关闭（即默认开启 `--fast`） | 即使新旧镜像的 `rpmdb.sqlite` 层摘要完全一致，也强制拉取并解析包表 |
| | `--no-audit` | 关闭（即默认开启 `--audit`） | 跳过“仍落后于已发布 `stable` 安全更新”的积压检查 |
| | `--prune-days N` | `14` | 分析完成后清理超过 `N` 天的旧包表缓存（保留本次对比的两个镜像；`0` 为不清理） |
| | `--fail-on {nothing,security}` | `nothing` | 设为 `security` 时，若结论为 `update-now` 则以退出码 `10` 结束（专供 CI 使用） |

> **标准输出流说明**：当使用 `layers`/`pkgs` 的 `--json -` 或 `diff`/`backlog` 的 `--json-out -`（以及 `/dev/stdout`）时，标准输出（`stdout`）只会写入干净的 JSON 文档，所有进度提示与诊断信息均发往标准错误（`stderr`）。工具会在发起任何网络请求前检查输出路径冲突，防止报告、JSON、状态文件或标准输出重定向指向同一个文件而互相覆盖。

### 常用示例

```bash
# 1. 查看近期构建历史，获取不可变的 sha256 digest
python3 sbwatch.py history --image secureblue/silverblue-main-hardened

# 2. 快速查看两个版本之间的分块变化与预计下载体积（旧 -> 新）
python3 sbwatch.py layers 20260916 latest --image secureblue/silverblue-main-hardened

# 3. 完整精确对比，输出双语 Markdown 报告与结构化 JSON
python3 sbwatch.py diff 20260916 latest --markdown diff.md --json-out diff.json

# 4. 秒级仅 Manifest 预览（只下载 ~50KB Manifest，不拉取 ~33MB rpmdb）
python3 sbwatch.py diff 20260916 latest --exact 0

# 5. 开启 Cosign 签名强制校验（校验结果会写入报告）
python3 sbwatch.py diff 20260916 latest --cosign-pub ./cosign.pub --require-cosign

# 6. 单独审计当前最新镜像还落后 Fedora 多少已发布的 stable 安全更新
python3 sbwatch.py backlog latest --max-bodhi 80

# 7. CI / 定时监控模式：仅当标签指向新构建（或上次分析未完成）时执行完整对比
python3 sbwatch.py check \
  --image secureblue/silverblue-main-hardened \
  --to latest \
  --cosign-pub ./cosign.pub --require-cosign \
  --report report.md
```

---

## 升级建议（Verdict）与安全判定规则

### 六种结论级别

每次运行 `diff` 或 `check`，工具都会在 `verdict.level` 中给出以下六种结论之一，并附带一句机器可读的英文判定依据 `verdict.level_basis`（例如 `2 source package(s) carry security evidence`、`the kernel moved`、`secureblue's own notification rule classifies this as major`）：

| `verdict.level` | 报告徽章（中 / 英） | 判定条件与含义 | 行动建议 |
| :--- | :--- | :--- | :--- |
| **`update-now`** | `[!] 立即更新` / `[!] UPDATE NOW` | 包含 CVE 修复、已发布的 `stable` 安全勘误、高/严重级别（Important/Critical）勘误，**或触发了 secureblue 的「重大（major）」桌面通知规则** | 立即执行 `rpm-ostree upgrade && systemctl reboot` |
| **`consider`** | `[~] 可选更新` / `[~] OPTIONAL` | 未发现直接归属本次升级的 CVE/安全勘误，但存在以下任一情况：<br>1. `kernel` 软件包版本变化；<br>2. 安全敏感包（`IMPORTANT_SRC`）版本升级；<br>3. 安全敏感包版本未变但独立分块摘要变化（`silent_important`）；<br>4. 存在**软件包版本降级**；<br>5. Bodhi 勘误查询未完整覆盖（无法证实“无安全修复”）；<br>6. 镜像仍落后于已发布的 **Important/Critical** 级 `stable` 安全更新 | 结合下载体积与变更内容决定是否升级 |
| **`skip`** | `[ok] 可跳过` / `[ok] SKIP OK` | 常规软件包日常更新（或仅 `initramfs` / `rpmdb` 等非包层变化），无 CVE、无安全勘误、无敏感包异动 | 若在意下载流量可安全跳过 |
| **`no-change`** | `[ok] 软件包无变化` / `[ok] NO PACKAGE CHANGE` | **已读取包版本（或确认两侧 `rpmdb.sqlite` 分块摘要一致）**，且所有软件包的集合与 NEVRA 完全未变，无安全敏感包分块异动。<br>*注：NEVRA 相同不证明层内文件逐字节相同；不属于任何 RPM 包的无归属文件（`chunkah/unclaimed` 与 `bigfiles/*`）若发生变化会在标题中注明未检查的压缩层体积* | 就 RPM 软件包而言无需更新 |
| **`no-update`** | `[ok] 无新构建` / `[ok] NO NEW BUILD` | `check` 模式下，被监控标签解析出的平台镜像 digest 与上次完整分析时完全一致 | 远端无新镜像，无需操作 |
| **`unknown`** | `[?] 未知` / `[?] UNKNOWN` | 未读取软件包版本（`--exact 0`）、`rpmdb` 解析不完整（包头损坏、字段跳过、同名包遮蔽或空表）、更新日志扫描触发上限，或 `check` 未找到可对比的基线镜像 | **信息不足，不能据此认为“可跳过”** |

### 安全证据来源细分（`security_basis`）

为了明确区分每一项安全结论到底建立在什么证据之上，`verdict.security_basis` 会按源码包给出以下五种具体标签之一：

1. **安全勘误（`security erratum`）**：  
   新镜像安装的构建精确匹配了 Fedora Bodhi 中已发布（`status=stable`）且类型为 `security` 的勘误。
2. **对应 Fedora 勘误 / 归一化匹配（`corresponding Fedora erratum`）**：  
   软件包带有 `secureblue` 的本地发行号后缀（例如 `kernel-7.2.8-200.secureblue.1.fc44`），剥离 `.secureblue.N` 后匹配上了 Fedora 上游的 `kernel-7.2.8-200.fc44` 安全勘误。这证明镜像确实合入了对应的上游修复（计入报告与 `update-now` 结论），但本机 `rpm-ostree` 不会将其关联为系统勘误（因此**不计入**桌面通知预测）。
3. **被越过构建的安全勘误（`security erratum of a passed-over build`）**：  
   在同一 Fedora 大版本内跨版本升级时（例如从 `8.9.0` 直接升到 `8.9.3`），中间被跳过的构建（`8.9.1`，满足 `旧版本 < 该构建 <= 新版本`）带有已发布的 `stable` 安全勘误。虽然新旧两个镜像中都未直接出现 `8.9.1`，但其安全修复已随 `8.9.3` 一并到达，因此记录在 `passed_over` 中并计入安全结论（同样不驱动桌面通知预测）。
4. **非安全类勘误，含 CVE 或高严重度（`non-security erratum (CVE ids or high severity)`）**：  
   Bodhi 中勘误类型为 `bugfix` 或 `enhancement`，但该勘误达到了 `high`/`urgent` 严重度，或单源码包勘误自身列出了 CVE 编号。
   - **多源码包勘误的 CVE 归属边界**：当一条 `type=security` 的勘误包含多个源码包构建时（如底层库更新附带依赖包重编译），其关联的 CVE 属于整条勘误而非每个子包，因此会单列在 `advisory_wide_cves` 中（报告中有专门小节说明，同时汇总进 `verdict.cves`）。而当一条**非安全类（如 `bugfix`/`enhancement`）**的多源码包勘误（例如包含 738 个构建的 OpenSSL 4.0 批量重建）在 Bug 列表中提到了其它包的 CVE 时，工具不会将该 CVE 错误归因给任何一个陪跑重建的包。
5. **更新日志 CVE（`changelog CVE`）**：  
   仅当新版 RPM 相比旧版**新增**的更新日志条目中出现了 CVE 编号（且未被保留的旧日志条目提及）时，才会标注为此项。

### 降级（回滚）与“不再提及的 CVE”处理

- **版本降级（`downgrades`）与被回退的勘误（`errata_reverted` / `reverted_errata`）**：
  - 当更新（或标签回滚）导致软件包版本倒退时，报告会在最上方展示「**本次更新中的降级——请先阅读**」小节，并将原本为 `skip` 的结论抬升至 `consider`。
  - 降级发生时，工具会查询**被离开的旧构建**本身、以及回滚过程中**逆向越过的中间构建**（同一 Fedora 版本内满足 `新版本 < 中间构建 <= 旧版本`）是否带有已发布的 `stable` 安全勘误。若有，会在标题和 `verdict.errata_reverted` / `changed[].reverted_errata` 中点名警告“此次更新会回退已发布的安全勘误”。
  - 同时，降级目标（更老的那个版本）自己当年携带的勘误或 CVE **绝不会**被当成“本次更新带来的新修复”，防止回滚被荒谬地判为 `update-now`。
- **更新日志中不再提及的 CVE（`cves_dropped` 与 `cves_reverted`）**：
  - **`cves_dropped`（常规日志裁剪提示）**：如果软件包版本正常向前升级，但旧版更新日志里提到的某个 CVE 在新版日志中消失了，这通常只是维护者裁剪了旧日志，或内核跨版本变基时重新生成了日志。工具只将其作为提示列出（「新版更新日志不再提及的 CVE 编号」），**不称其为“移除了修复”，也不抬高风险等级**。此外，若新构建命中的已发布 Bodhi 勘误中仍包含该 CVE，工具会自动消除这一假阳性。
  - **`cves_reverted`（降级导致的真实回退警告）**：如果消失的 CVE 来自一个**本次被降级的软件包**，工具会将其归入 `cves_reverted`，并在标题与正文中发出明确警告：降级很可能真正回退了这些 CVE 修复。

---

## secureblue 桌面通知预测

### 上游弹窗判定规则

`secureblue` 在桌面会话中通过脚本 `files/system/desktop/usr/libexec/secureblue/security-update-notification` 决定是否在更新暂存后弹出系统通知：

1. **纯 `bootc` 镜像分支**：  
   若当前启动的旧镜像安装了 `bootc` 而没有 `/usr/bin/rpm-ostree`，脚本会读取 `/run/bootc/status.json`——只要存在已暂存的部署（staged deployment），就会**无条件**弹出 `urgency=critical` 的 `"An update is ready"` 通知。`sbwatch` 检测到旧镜像处于此模式时，会将 `unconditional` 标记为 `true`（由于该弹窗与更新内容无关，不会因此将 `verdict.level` 强制抬升为 `update-now`）。
2. **标准 `rpm-ostree` 分支**：  
   脚本读取 `rpm-ostree status --json` 的 `.cached-update` 字段：
   - **重大通知（`level = "major"`，`urgency=critical`，附带重启提示）**：  
     消息内容：`"A major security vulnerability has been patched"`  
     触发条件：`trivalent` 出现在 `.rpm-diff.upgraded` 中，**或者** `.advisories` 中安全勘误的最高严重等级为 `critical`。
   - **普通通知（`level = "normal"`，`urgency=normal`）**：  
     消息内容：`"A security vulnerability has been patched"`  
     触发条件：`kernel` 出现在 `.rpm-diff.upgraded` 中，**或者** `.advisories` 中安全勘误的最高严重等级属于 `{important, unknown}`。
   - **不弹通知（`level = "none"`）**：不满足以上条件。

> 当 `sbwatch` 预测一次正向更新会触发 `secureblue` 的 **`major`（重大）** 通知时，会将整体的 `verdict.level` 强制上调至 **`update-now`**——因为发行版维护者已用最高紧急度提示用户立即重启。

### 三个关键实现细节

#### 1. 勘误分支仅在「叠加了软件包（layered packages）」的系统上生效

在 `rpm-ostree` 源码中，只有当升级器持有本次更新的 `rpm-md` 仓库元数据时（`rpmostreed_update_generate_variant()` 中的 `if (sack && ...)`），才会计算 `.advisories`；而升级器只有在系统 origin 叠加了额外软件包时（`prep_local_assembly()` 检查 `rpmostree_origin_has_any_packages()`）才会保留这份元数据。

- **未叠加任何软件包的默认安装系统（stock install）**：没有 `.advisories` 字段，通知脚本读到的最高勘误等级恒为 `none`，**只有 `trivalent` 或 `kernel` 升级才会触发桌面弹窗**。
- **叠加了软件包的系统**：拥有本地 `rpm-md` 时，才会额外触发基于勘误严重度的弹窗分支。

因此，`sbwatch` 在 `verdict.secureblue_notification` 中同时给出：
- `level`：按「有勘误元数据（叠加包系统）」预测的结果；
- `level_without_advisories`：默认安装（无叠加包系统）会看到的结果；
- `advisory_driven`：当两者不同时为 `true`，报告正文与标题会同时写明两种系统下的行为差异。

#### 2. 勘误严重度只认「精确 EVR 命中」，且新增包不参与查询

- `rpm-ostree` 调用 `libdnf` 的 `dnf_package_get_advisories(pkg, HY_EQ)` 匹配勘误，只有当 `pool_evrcmp(勘误 EVR, 包 EVR) == 0`（包含 `release` 字符串逐字相等）时才会挂载到 `.advisories`。
- 因此，`secureblue` 自编译的内核（如 `7.2.8-200.secureblue.1.fc44`）**不会**在 `rpm-ostree` 中匹配上 Fedora 的 `7.2.8-200.fc44` 勘误，也就不会通过勘误分支触发通知（内核升级本身会走 `kernel_updated` 分支触发 `normal` 通知）。
- 此外，`rpm-ostree` 只将版本发生变化的包（升级或降级）送去查询 `.advisories`，本次镜像**新加入的包（`added`）**不在此列，因此新增包上的勘误不会驱动通知预测。

#### 3. Bodhi 严重度词表到 `rpm-ostree` 的转换链路

Fedora 的 `updateinfo.xml` 确实发布了严重度，只是写在 `<update>` 的**子元素 `<severity>`** 中（而非 XML 属性 `severity=`）。Bodhi 在生成 `updateinfo.xml` 时会先调用 `severity_updateinfo_str()` 将 Bodhi 内部词表映射为 RHEL 标准词表，随后由 `libsolv` 解析并交给 `rpm-ostree` 的 `str2severity()`：

| Bodhi API 勘误 `severity` | `updateinfo.xml` `<severity>` 子元素 | `rpm-ostree` 转换值 → 脚本分支 | 桌面弹窗行为 |
| :--- | :--- | :--- | :--- |
| `urgent` | `Critical` | `4` → `critical` | **重大通知（`major`）** |
| `high` | `Important` | `3` → `important` | **普通通知（`normal`）** |
| `medium` | `Moderate` | `2` → `moderate`（脚本无此分支） | **不弹窗（`none`）** |
| `low` | `Low` | `1` → `low`（脚本无此分支） | **不弹窗（`none`）** |
| `unspecified` / 缺失 | `None` | `0` → 落入默认分支 `*)` → `unknown` | **普通通知（`normal`）** |

- `sbwatch` 严格复现了这一转换过程（若直接把 Bodhi 原词传给 `str2severity()`，`urgent` 会被漏判为普通通知，而本不弹窗的 `medium` 又会被误判为普通通知）。
- **关于 `trivalent`**：`trivalent` 是 `secureblue` 自建包，不在 Fedora Bodhi 中发布，且上游每次仅在跟进 Chromium CVE 修复后构建新版本，因此上游脚本与 `sbwatch` 均直接按包名将任何 `trivalent` 升级判定为**重大通知（`major`）**，且不为它消耗 Fedora Bodhi 查询预算。
- **弹窗资格与日历日去重说明**：`sbwatch` 预测的是镜像变更本身是否**具备触发通知的资格（eligibility）**。实际桌面上，上游脚本还会在弹窗前检查用户目录下的每日时间戳文件（按本地日历日期比较，而非滚动 24 小时）：若当天已弹过重大通知则抑制后续所有通知，若当天已弹过普通通知则抑制后续普通通知。

### 通知预测 JSON 结构

```json
{
  "level": "major",
  "message": "A major security vulnerability has been patched",
  "level_without_advisories": "major",
  "advisory_driven": false,
  "max_advisory_severity": "unknown",
  "kernel_updated": true,
  "trivalent_updated": true,
  "security_advisory_count": 1,
  "why": [
    "trivalent upgraded (secureblue treats every Trivalent bump as major: Trivalent is rebuilt when upstream Chromium CVEs land)",
    "kernel upgraded",
    "security advisory with rpm-ostree severity 'unknown'"
  ],
  "why_zh": [
    "trivalent 已升级（secureblue 将任何 Trivalent 更新视为重大：在上游 Chromium 修复 CVE 时重新编译）",
    "内核已升级",
    "存在 rpm-ostree 严重等级为 'unknown' 的安全勘误"
  ]
}
```

> 当包版本未读取（`--exact 0`）、包表不完整，或在叠加包系统上相关包的 Bodhi 勘误覆盖不完整且尚未确定达到 `major` 时，`level` 会返回 `unknown`。

---

## 进阶机制与报告约定

### `--exact 0`（仅 Manifest 模式）与 `check --fast`

- **`--exact 0` 的语义**：
  - 只拉取并对比两个镜像的 OCI Manifest（约 50 KB），不下载 33 MB 的 `rpmdb.sqlite`。
  - **能得到**：需要重新下载的字节数、分块复用率、哪些包名落在了发生变化的 chunk 中（注：一个捆绑分块变化时，其中的数十个包都会被列出；实测某次更新 `--exact 0` 显示 241 个包位于变化的分块中，而 `--exact 1` 解析 `rpmdb` 后确认真正变动的只有 8 个包）。
  - **得不到**：任何软件包的具体版本号。因此该模式不做包 diff、不匹配 CVE 或勘误、不断言“哪些包版本未变”，`verdict.level` 与通知预测一律为 **`unknown`**（绝不会给出具有误导性的 `skip` 徽章）。
- **`check --fast` 的安全快速路径**：
  - `check` 默认开启 `--exact 1` 与 `--fast`。
  - 当两个镜像的 **`rpmdb.sqlite` 层摘要（digest）完全相同**时，说明两侧的 RPM 数据库逐字节一致，包集合与版本必然没有任何变化：
    - 若未开启 `--audit`（如传入了 `--no-audit`），工具会直接跳过 33 MB 的 `rpmdb` 下载，安全降级为仅 Manifest 对比并给出 `no-change` 结论；
    - 若开启了默认的 `--audit`（需要检查镜像是否落后于 Fedora 新发布的 `stable` 安全勘误），工具只需下载/读取**一次**共享的包表，不再对第二个镜像重复下载或解析。
  - 如需在任何情况下都强制禁用此快速路径，可传入 `--no-fast`（或在 GitHub Actions 手动触发时勾选 `force`）。

### Cosign 签名校验与端到端完整性保护

当传入 `--cosign-pub ./cosign.pub`（及 `--require-cosign`）时：

1. **摘要级签名验证**：调用 `cosign verify --key` 对解析出的**平台 Manifest 摘要（digest）**进行签名验证（同一进程内对相同 digest 自动去重，避免重复网络往返）。
2. **全链路内容哈希校验**：因为 `cosign` 只对 digest 签名，若不校验 Registry 实际返回的字节内容，“签名通过”就只证明了名字而没证明数据。为此，`sbwatch` 对按 digest 取回的 **Manifest、镜像 Config 以及 `rpmdb.sqlite` 层数据流**逐一计算并核对 `sha256:<64 hex>`，一旦内容与摘要不符立即中止分析并清理临时文件。
3. **元数据信任边界**：分析所使用的版本号、构建时间等元数据仅取自经过摘要验证的平台 Manifest 及其 Config，不使用外层多架构 Index 描述符上的未验证注解。（注：签名证明该镜像由发布方构建，但不能证明可变标签未被指向旧的合法构建。）

### Bodhi 调用预算、缓存与断点续查

- **预算共享与优先级排序**：
  - 在 `diff` 和 `check` 中，变更包的勘误分类与 `--audit` 安全积压审计**共享同一个 `Bodhi` 实例、同一个 `--max-bodhi` / `--bodhi-seconds` 预算和同一份缓存**（例如 `--max-bodhi 10` 严格最多发起 10 次 HTTP 调用）。
  - 查询顺序始终优先保障安全敏感源码包（`IMPORTANT_SRC`），防止普通字体或图标包耗尽调用预算。
  - 第三方构建的 RPM 包（通过 RPM `Vendor != "Fedora Project"` 识别，如 `negativo17.org` 的多媒体包、Copr 仓库包、NVIDIA 驱动，以及无 Vendor 的 `trivalent` / `zfs` / `nvidia-kmod`）会自动排除在 Fedora 勘误查询之外，既避免 NVR 巧合撞名造成误报，也节省 API 调用（带有 `.secureblue.N` 后缀的 Fedora 内核重编译包仍正常查询）。
- **断点续查与 `analysis_incomplete`**：
  - 当某次 `check` 因偶发网络错误、`--max-bodhi` / `--bodhi-seconds` 预算耗尽或分页截断导致勘误未能全部查完时，输出 JSON 与 `state.json` 中的 `analysis_incomplete` 会被设为 `true`。
  - 已成功查完的源码包结果会写入缓存（TTL 6 小时），读取到一半且页码连续可验证的 Bodhi 多页响应也会保存为 `.partial.json` 进度文件（TTL 从第 1 页起算；若后续续查发现总条数或分页发生漂移则自动丢弃重查）。
  - **自动补查**：下次运行 `check` 时，即便远端标签的 digest 没有变化，只要上次状态标记为 `analysis_incomplete: true`（或 `last_verdict == "unknown"`，或用户修改了 `--exact`、`--no-bodhi`、`--no-audit`、`--backlog-candidates` 等分析范围参数），工具都会**自动沿用上次记录的有效对比基线（`prev_digest`）继续补查**，使小预算环境也能跨多次运行逐步完成完整审计。（显式指定 `--no-bodhi` 或 `--backlog-candidates` 造成的人为范围收缩不视为未完成，不会导致无限重试。）

### 拒绝静默截断（Truncation Disclosure）与双语排版

- **中英独立双语报告**：生成的 Markdown 报告采用**纯中文上半区 + `---` 分隔线 + 纯英文下半区**的独立结构，两部分互不混杂。
- **显式截断披露**：报告中任何因可读性或单元格宽度而被截断的列表/文本，都会明确写出被省略的数量（如 `（另有 12 个源码包未显示）`）。
- **超长 CVE 完整清单**：安全变更表的「CVE 编号」列每行最多展示 6 个编号；一旦某个源码包关联的 CVE 超过 6 个（例如单次 `webkitgtk` 更新携带 113 个 CVE），表格正下方会自动附上「**上表未列全的 CVE：完整清单**」小节，一字不漏地列出全部编号。同时，`--json-out` 与 `$GITHUB_OUTPUT` 始终输出未经任何截断的完整列表与计数。

### JSON 输出结构与摘要标识说明

在 `diff` 和 `check` 导出的 JSON 文件（如 `report.md.json`）中：

- **对比端点与被监控标签标识**：
  - `from` / `from_digest` / `from_index_digest`：标识本次对比的**基线镜像（较旧一方）**。
  - `to` / `digest` / `index_digest` / `version`：标识本次对比的**目标镜像（较新一方）**。
  - `watched_digest` / `watched_index_digest` / `watched_version`（仅 `check` 模式）：独立标识**当前被监控标签（`--to`）所指向的镜像**。当用户通过 `--a` 传入了一个比当前监控标签更新的引用、触发自动时间顺序交换时，`digest` 是对比目标，而 `watched_digest` 依然准确记录被监控标签本身的摘要（`$GITHUB_OUTPUT` 中同样区分这两个键）。
  - *Index Digest vs Platform Digest*：`*_index_digest` 是顶层多架构 OCI Index 的摘要，而 `from_digest` / `digest` / `watched_digest` 是对应 `--arch` 架构的具体平台 Manifest 摘要。
- **结构化软件包身份字段（NEVRA）**：
  - `changed` 数组中的每一项除了保留便于阅读的 `old` / `new` 版本字符串外，还提供机器友好的 `old_nevra` 与 `new_nevra` 对象（包含 `name`、`epoch`、`version`、`release`、`arch` 五个字段，即使两侧的非零 `epoch` 未发生变化也会完整保留）。
  - 新增与移除的软件包除了名称列表 `added` / `removed` 外，同样提供完整的 `added_nevra` 与 `removed_nevra` 列表。
  - `rpmdb_issues` 与 `changelog_scan_incomplete` 分别记录 RPM 包表解析异常统计与触发扫描条数上限（每包新增/丢失/保留各 1000 条）的软件包名。

### 退出码约定

- **正常执行一律返回 `0`**：所有子命令只要正常跑完分析流程，无论得出的 `verdict.level` 是 `skip`、`consider`、`update-now` 还是 `unknown`，进程退出码均为 **`0`**（外部脚本或 CI 应从 `--json-out` 或 `$GITHUB_OUTPUT` 中读取结论）。
- **运行错误返回非零（如 `1` / `2`）**：仅当发生命令行参数错误、输出路径冲突、网络或 Registry 请求失败、`rpmdb` 结构损坏或强制签名校验失败时，才返回非零退出码。
- **唯一显式例外（退出码 `10`）**：在执行 `check --fail-on security` 时，若结论为 `update-now`，程序会以退出码 **`10`** 退出，专供 CI 工作流识别并点亮安全告警状态。

---

## GitHub Actions 自动化监控

仓库内置了完整的自动化监控工作流 [`.github/workflows/sbwatch.yml`](.github/workflows/sbwatch.yml)。

### 工作流特性

1. **触发机制**：
   - **定时运行（`schedule`）**：内置每小时第 20 分钟（`20 * * * *`）的 cron 计划。（*注：GitHub Actions 公共定时队列常常延迟，数小时才执行一次。因此，我做了 [worker-cron](https://github.com/lingyicute/worker-cron)，每半小时就触发一次。*）
   - **手动触发（`workflow_dispatch`）**：支持在 Actions 页面按需指定镜像、架构、对比基线标签（`from_tag`）或强制重跑（`force`）。当手动指定 `from_tag` 时，工作流会使用临时状态文件，仅复用包表与 Bodhi 缓存，**不会覆盖定时监控的 `state.json` 基线，也不会向 Issue 或 Telegram 发送告警**，但仍会生成运行摘要（Step Summary）并上传报告 Artifact。
   - **代码推送（`push` 到 `main`）**：触发独立的离线回归测试与 `pyflakes` 静态检查作业（`Tests` 作业仅在 `push` 时运行，且与 `Update watch` 作业完全并行、互不阻塞）。
2. **缓存隔离与自动生命周期管理**：
   - 使用 `actions/cache` 缓存 `~/.cache/sbwatch`（含包表缓存、Bodhi 缓存与 `state.json`），缓存键按 **`镜像名称命名空间 + 架构`** 严格隔离，防止 `amd64` 与 `arm64` 或不同镜像之间互相挤占。
   - `check` 每次完成对比后，会自动删除超过 **14 天**的旧包表缓存（刚对比完的两个镜像除外，平均每个镜像包表约 11 MB）、超过 **6 小时 TTL** 的过期 Bodhi 缓存，以及意外中断留下的超过 **1 小时**的 `*.json.tmp.<pid>` 临时文件。
   - 当运行结论为 `no-update` 时，由于缓存目录没有任何新写入，工作流会跳过缓存保存步骤；而在有更新并保存新缓存后，会通过 GitHub API 自动清理当前分支、当前命名空间下的旧缓存，**仅保留最新创建的 7 份**，防止 `state.json` 被 GitHub Actions 的缓存容量淘汰策略挤掉。
3. **时间预算与签名安全锚点**：
   - 工作流调用 `check` 时传入 `--max-bodhi 100 --bodhi-seconds 600`，将 Bodhi 网络查询总耗时限制在 10 分钟以内，为后续生成报告、上传 Artifact 与推送通知预留充足时间。
   - 仓库内提交的 `cosign.pub` 在运行前会先校验 SHA256（比对工作流环境变量 `COSIGN_PUB_SHA256`），拒绝在运行时从网络拉取未经审计的密钥；若上游轮换密钥会立即显式报错，而非静默改变“验证通过”的含义。Step Summary 中附加的近期构建历史同样逐条强制校验签名。
4. **多渠道通知与监控失效保护**：
   - **Sticky Issue 评论**：当结论为 `update-now` 或 `consider`（若开启 `POST_SKIP_VERDICT=true` 则包含 `skip`）时，自动向标题精确为 `secureblue update watch` 的 Open Issue 发表评论（不存在则自动创建；若报告超过 GitHub 评论的 65,536 字符上限则安全截断并引导查看 Run Summary / Artifact）。
   - **Telegram 推送**：若配置了 `TELEGRAM_BOT_TOKEN` 与 `TELEGRAM_CHAT_ID` Secrets，会将摘要与报告推送到 Telegram（按 UTF-16 代码单元精确截断在 4,096 字符限制以内）。若只配置了其中一个 Secret 或 Telegram 发送失败，该步骤会报错退出且**跳过后续的缓存保存步骤**，从而保证下次定时运行能够基于原基线自动重试投递。
   - **`unknown` 结论红牌告警**：当结论为 `unknown`（例如无法获取对比基线或 Registry 探测失败）时，工作流会在上传完诊断报告 Artifact 后**主动以失败状态（红色）退出**，确保监控失效能够第一时间被察觉，而不会伪装成“本周无事发生”的绿灯。

### 配置项（输入参数、Variables 与 Secrets）

#### 手动触发参数（`workflow_dispatch` inputs）

| 参数名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `image` | `secureblue/silverblue-main-hardened` | 要检查的 GHCR 镜像仓库（`namespace/name`） |
| `arch` | `amd64` | 架构选择：`amd64` 或 `arm64` |
| `from_tag` | 空（使用上次记录的状态基线） | 一次性与指定标签（如 `20260916`）进行对比 |
| `force` | `false` | 即使镜像 digest 未变也强制重新分析 |

#### 仓库变量（Settings → Secrets and variables → Actions → **Variables**）

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `POST_SKIP_VERDICT` | `false` | 设为 `true` 时，即使结论为 `skip` 也会发布到 Sticky Issue 与 Telegram |
| `FAIL_ON_SECURITY` | `false` | 设为 `true` 时，向 `sbwatch` 传入 `--fail-on security`，遇到 `update-now` 安全更新时让工作流标红（退出码 `10`） |

#### 仓库机密（Settings → Secrets and variables → Actions → **Secrets**）

| Secret 名称 | 是否必填 | 说明 |
| :--- | :--- | :--- |
| `TELEGRAM_BOT_TOKEN` | 可选（需与 `TELEGRAM_CHAT_ID` 成对配置） | Telegram Bot 的 API Token |
| `TELEGRAM_CHAT_ID` | 可选（需与 `TELEGRAM_BOT_TOKEN` 成对配置） | 接收推送的目标频道、群组或用户 Chat ID |

---

## 安全加固与离线回归测试

`tests/` 目录包含一套全面的**纯离线回归测试套件**。测试运行器会直接拦截底层的 `socket.socket.connect`，确保测试全程零网络请求、不访问任何外部 Registry 或 Bodhi 服务，也不依赖本机安装 `rpm`：

```bash
python3 tests/run_offline.py
```

测试套件锁定的核心行为与安全边界涵盖以下六个维度：

1. **RPM 版本比较与数据库解析精确性**：
   - `rpmvercmp` 完整移植自 RPM 上游 `rpmio/rpmvercmp.cc`，100% 通过 RPM 官方测试集 `tests/rpmvercmp.at` 的全部 **103 条测试向量**（离线保存在 `tests/rpmvercmp_vectors.json` 中，涵盖 `~` 预发布符、`^` 快照后缀、数字段优先于字母段、前导零归一化等边界情况）。
   - 正确处理缺失 Epoch 与显式 `Epoch: 0` 的等价性，确保纯 Epoch 变化在 diff 与 JSON 中清晰可见，且同源子包正确继承主包的构建 Epoch。
   - 兼容活镜像 `rpmdb.sqlite` 层内存在同名 0 字节占位符的情况（按文件大小择优并支持解析多级相对/绝对软硬链接），并在临时目录名含特殊字符（`#`、`?`、`%`）时通过 URI 安全只读打开。
   - 严格校验 RPM Header 标签编号（`1011` Vendor、`1014` License，不误将 `1010` Distribution 当作 Vendor），兼容多语言 `I18NSTRING` Summary/Description，完整统计并披露损坏包头、跳过字段与 multilib 同名遮蔽包。
2. **勘误匹配、CVE 归因与安全积压（Backlog）审计**：
   - 严格过滤匹配旧构建的勘误（`already_had`）与未推送至 `stable` 的勘误（`not_pushed`），防止旧修复或测试中勘误虚抬当前更新的严重度。
   - 支持从 Bodhi 的 `notes`、`title` 与 `bugs[].title` 中提取 CVE，兼容空格分隔（`CVE 2026-114583`）、特殊连字符、花括号展开（`CVE-2026-{1001,1002}`）及 4~19 位序号边界校验；若保留的旧更新日志条目仍提及某 CVE，则不会因重复条目增删而误报新增或丢失。
   - 区分精确 EVR 命中（`hit_attached`）与剥离 `.secureblue.N` 后的归一化匹配（`advisory_corresponding`）；使用安装的 SRPM 源码构建身份查询 Bodhi，支持无同名二进制包的源码包（如 `shim`、`webkitgtk`）及无 `.fcNN` 后缀的系统包。
   - 准确捕获跨版本升级时越过的中间构建安全勘误（`passed_over`），以及版本回滚时逆向越过或离开的安全勘误（`reverted_errata` / `errata_reverted`）。
   - 仅记录 Bodhi 明确返回的非零构建 Epoch（忽略 Bodhi API 常为 Epoch > 0 的包错误返回的默认 `"epoch": 0`），并按 RPM `Vendor` 自动过滤第三方仓库包（`negativo17.org`、Copr、NVIDIA、`trivalent` 等）。
3. **secureblue 桌面通知预测与 Verdict 决策**：
   - 全链路验证「Bodhi 原始严重度 → `updateinfo.xml` `<severity>` 子元素 → `rpm-ostree` `str2severity()` → 桌面通知脚本 `case` 分支」的 11 行真值表对拍。
   - 严格区分默认安装（`level_without_advisories`）与叠加包系统（`level`），验证 `trivalent` 升级抬升 `update-now` 时自动剥离冲突的“可跳过”文案，并覆盖纯 `bootc` 环境的无条件通知分支。
   - 锁定 `no-change` 判据必须建立在包表真实比对之上（绝不采信继承自基础镜像的 `rpmostree.inputhash`），且在 `--exact 0`、包表不完整或日志扫描截断时强制返回 `unknown`。
4. **有状态监控（`check`）、历史回溯与断点恢复**：
   - 验证 `build_history` 同时记录多架构 `index_digest` 与单架构 `platform_digest`，自动过滤 `-uki` 单架构镜像、`br-*`/`pr-*` 分支预览与无 `rpmdb` 的集成测试镜像，并锁定主版本流标签（如 `44`）的历史范围。
   - 验证 `check` 在状态基线对比时保留真实的标签回滚方向，在保存的基线被 Registry 清理（404）或损坏时平滑回退至构建历史 / 日期标签，并在 `analysis_incomplete` 或分析范围变更时自动沿用原基线重查。
5. **P0 资源边界与协议安全加固**：
   - 强制执行压缩层下载上限（200 MiB）、流式解压上限（320 MiB，拒绝层内嵌套压缩流）、JSON 文档上限（16 MiB）、Tar 成员数上限（10,000）与单文件上限（256 MiB）。
   - SQLite 禁用 `trusted_schema`，拒绝虚拟表、视图与生成列（`GENERATED COLUMNS`），防止恶意构造的微型数据库触发无限递归或内存膨胀。
   - 跨源重定向自动剥离 `Authorization` Bearer Token，拒绝 `file:`/`ftp:`/`data:` 等非 HTTP(S) 重定向与认证 Realm，强制校验分页 `Link` 头同源性，校验所有按 digest 获取的内容哈希，并在失败时清理残留临时文件。
6. **输出完整性、双语隔离与 CI 供应链保护**：
   - 验证中英文报告半区彻底隔离、Markdown 表格管道符与换行符安全转义、每一处列表/文本截断均显式附带省略计数、安全表溢出 CVE 自动生成完整清单小节。
   - 验证原子文件写入、设备文件（`/dev/stdout`）与符号链接写入兼容性、输出路径冲突拦截、`$GITHUB_OUTPUT` 随机分隔符防注入，以及 GitHub Actions 工作流的 Commit SHA 固定与最小权限配置。

---

## 许可

本项目以 **GNU Affero General Public License v3.0 (AGPLv3)** 许可证开源。

Copyright (C) 2026 lingyicute.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file or <https://www.gnu.org/licenses/> for more details.
