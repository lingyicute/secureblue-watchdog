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

> [!tip]
> **severity 只取「精确 EVR 命中」。** rpm-ostree 用
> `dnf_package_get_advisories(pkg, HY_EQ)` 填充 `.advisories`，libdnf 只在
> `pool_evrcmp(勘误 EVR, 包 EVR) == 0` 时才认（`libdnf/sack/query.cpp`，
> `Query::getAdvisoryPkgs`）——release 字符串参与比较。
> 所以 secureblue 自建的内核 `7.2.8-200.secureblue.1.fc44` **不会**因为 Fedora 有
> `7.2.8-200.fc44` 的勘误而弹窗。`sbwatch` 现在同样处理：这类命中标为
> 「对应 Fedora 勘误（归一化匹配）」，**计入报告与 CVE 判定，但不计入通知预测**；
> 反过来，`.advisories` 覆盖「新部署里所有变化的包」，**包含本次新增的包**，
> 所以新增包上的勘误也会驱动预测。

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

**1. severity 有发布，只是不在属性里。**
Fedora 的 updateinfo.xml 里 severity 不在 `<update>` 的**属性**里——grep `severity=`
一条都没有，很容易误判成「Fedora 不发布 severity」——而是在**子元素**
`<severity>` 里；libsolv 的 updateinfo 解析器（`repo_updateinfoxml.c`）读的正是子
元素，rpm-ostree 的 `dnf_advisory_get_severity()` 拿到的就是真值。Bodhi 发布前还会
先把自己的词映射成 RHEL 拼写（`bodhi/util.severity_updateinfo_str()`，
bodhi#2099 早在 2018-01 就落地了）。实测 F44 updates 仓库（2026-09-24）：
2979 条 `<update>` **全部**带 `<severity>` 子元素，其中 security 类含
Important=112、**Critical=13**（含 2026-09-22 的 chromium）。

| Bodhi 勘误 severity | 发布为 | rpm-ostree → secureblue 分支 | 桌面行为 |
|---|---|---|---|
| `urgent` | `Critical` | 4 → `critical` | **重大** |
| `high` | `Important` | 3 → `important` | 普通 |
| `medium` | `Moderate` | 2 → `moderate`（无此分支） | **不弹** |
| `low` | `Low` | 1 → `low`（无此分支） | **不弹** |
| `unspecified`/缺失 | `None` | 0 → `*)` → `unknown` | 普通 |

所以 `major` 有两条触发路径：**trivalent 升级**，或**存在 Bodhi `urgent` 级安全勘误**。
`sbwatch` 存的就是映射后的拼写再喂 `rpmostree_str2severity()`（若直接喂 Bodhi 原词：
`urgent` 会被低估成普通、`medium` 会被高估成普通——两个方向都错）。

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
# 仓库已自带 secureblue 的 cosign 公钥 cosign.pub（sha256 钉在 workflow 的 COSIGN_PUB_SHA256），
# 签名校验直接用它；重新下载只会覆盖这份核对过的文件
python3 sbwatch.py --help
```

依赖：Python 3.10+，仅标准库。`cosign` 二进制可选，用于 `--cosign-pub` 校验。

## CLI

```bash
sbwatch tags                  # 当前镜像 + 近期 dated tag
sbwatch history               # 列出最近 N 次真实构建 (通过 sig 标签发现，处理一天多推)
sbwatch layers A B            # chunk 级别 diff + 预估下载大小
sbwatch pkgs [ref]            # 某个镜像的精确包列表
sbwatch diff A B              # 精确包 diff + CVE 分类
sbwatch backlog [ref]         # 这个镜像还缺哪些已发布的 stable 安全更新
                              #   --backlog-candidates N：审计最多看多少个候选源码包（默认 45）
sbwatch check                 # 有状态的 digest watch，用于 CI/cron -> report.md + verdict + $GITHUB_OUTPUT

# A/B/ref 可以是：
#   latest | 44 | 20260916 | 9ec80ca-44 | sha256:<digest>
# 推荐用 digest，因为 dated tag 是可变的
# --image ns/name:44 里的标签会成为 --to / ref 的默认值（显式给出的 --to / ref 优先）
```

>[!important]
>
> ⚠️ `diff A B` / `layers A B` 中的 A 必须是【较旧】的一方，B 是【较新】的一方。
>
> 写反了会得出完全相反的结论（把新镜像里新增的 CVE 修复列进「新版更新日志不再提及的 CVE 编号」）。
>
> 工具现在会用 `org.opencontainers.image.created` 自动纠正顺序并在报告里说明；
> 
> 如需强制保持你给的顺序，加 --keep-order。

>[!tip]
> 先用 `sbwatch.py history` 或 `sbwatch.py tags` 确认哪个 tag 更新。

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
#            无法判断 kernel/trivalent 是否升级；通知预测与 verdict 级别本身
#            都是 unknown（该模式不会给出 skip 之类的建议）。
#    实测同一对镜像：--exact 0 说"241 个包位于变化的 chunk 中"，
#    --exact 1 才知道真正变的只有 8 个。报告里会明确声明未读版本。

# 4. 带签名校验 (P0 加固)；校验结果会写进报告
python3 sbwatch.py diff 20260916 latest --cosign-pub ./cosign.pub --require-cosign
#    cosign 只对 digest 签名；sbwatch 会对按 digest 取回的 manifest、config 和 rpmdb blob
#    逐一校验 sha256，内容与 digest 不符即中止，因此「签名通过」覆盖到实际被分析的数据
#    --require-cosign 必须同时指定 --cosign-pub，否则在任何网络请求前报参数错误
#    history 同样遵守签名选项：启用时逐一校验所有列出的镜像

# 5. CI 模式：只有 tag 移动时才做重活
python3 sbwatch.py check --image secureblue/silverblue-main-hardened --to latest --report report.md
# check 的 --audit（默认开）与 diff 共用同一个 Bodhi 调用预算和同一份答案缓存：
# --max-bodhi 10 就是最多 10 次调用，不会再被内部悄悄放大到 45 次；候选上限用
# --backlog-candidates 单独控制
# 使用 state.json 中的上次镜像作基线时，check 保留「上次 → 当前」的实际方向；
# tag 回滚会报告降级，不会按时间反转成安全升级。显式 --a 仍遵守 --keep-order。

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
| `unknown` | 未读取包版本（`--exact 0`）或无法得出结论 | 需要更多信息，不能据此跳过 |

> `no-change` 的判据是**包集合为空**，不是 `rpmostree.inputhash` 相同——后者继承自
> Fedora base，相同也不能证明没变化（见上文）。`--exact 0` 未读版本时同样不会给出
> `no-change`，因为那时"没有包变化"无从证实；该模式的 `level` 会直接是 `unknown`
> （详见下面「`--exact 0` 的 verdict 语义」）。

每个级别都会带一句机器可读的 `verdict.level_basis`（英文），说明是什么把级别定下来
（例如 `the kernel moved`、`a released security erratum ranks 4/4`、
`secureblue's own notification rule classifies this as major`），
以及逐包的 `verdict.security_basis`，区分「安全勘误」「对应 Fedora 勘误（归一化匹配）」、
「被越过构建的安全勘误」「非安全类勘误（含 CVE 或高严重度）」与「更新日志 CVE」——
只有新版更新日志里真的出现了 CVE 编号，才会标成「更新日志 CVE」。


报告里会包含：
- **截断披露**：任何被砍掉的列表/文本都会写明「另有 N 个未显示」；安全表的 CVE 列超长时，
  紧随其后的小节会列出**全部**编号；`--json-out` 与 GITHUB_OUTPUT 始终是完整数据（另附计数）
- 下载量：`download_bytes / total_size_b / download_pct`
- `secureblue_notification`：桌面会弹哪个通知 + 触发原因（见上文）
- `silent_rebuilds`：版本没变但 chunk 变了（工具链/macro/文件重排）
- `downgrades`：这次更新把某个包**降级**了（真证据，会抬高级别；报告点名「回退」的是**被离开的
  那个构建**的已发布安全勘误，而不是降级目标自己的勘误）；`cves_dropped`：
  新版更新日志不再提到的 CVE 编号（通常是日志被编辑，只作提示、不再抬高级别）
- `backlog`：即使跳过，你仍暴露在多少已发布 stable 安全更新之外
- `passed_over`：被这次更新**越过**的中间构建所带的 stable 安全勘误（旧 < 该构建 ≤ 新，同一 Fedora 版本内）。
  两个镜像里都没有这个构建，所以它的勘误对不上任何一方，但修复随新构建一并到来——计入结论与 CVE，
  不计入通知预测（rpm-ostree 只把勘误挂在精确命中的构建上）；`security_basis` 中标为「被越过构建的安全勘误」
- `same_inputhash_but_packages_moved`：inputhash 相同但包确实动了（显式告警，别拿 inputhash 当无变化的证据）

### `--exact 0` 的 verdict 语义

manifest-only 模式只读 manifest，**没有任何软件包版本被读过**，所以它可以描述 chunk
变化与下载量，但不能给出建议：

- `verdict.level` = `unknown`（以前会是 `skip`，报告里显示「可跳过」徽章——一个从未
  读过任何包版本的运行不该看起来像一条建议）；
- `verdict.level_basis` 写明原因；headline 保留 chunk 级结论（几个 chunk 变了、多少包
  落在变化的 chunk 里、要下载多少）；
- `check` 默认 `--exact 1`；`--fast` 只在两个镜像的 **rpmdb chunk digest 相同** 时才
  降级为 manifest-only，此时 db 逐字节相同，结论依然成立。

### `check --fast` 与 manifest-only

`check` 默认带 `--fast`：当**两个镜像的 rpmdb chunk digest 相同**时，跳过 33MB 拉取、
自动降级为 manifest-only。这是安全的——rpmdb.sqlite 逐字节相同 ⟹ 包集合必然没变。

> [!important]
> 早期版本用 `rpmostree.inputhash` 相同作为跳过依据，那是错的（见上文）。实测最近
> 8 次构建的 7 对相邻组合：旧条件会跳过 **5 次**，而那 5 次的 rpmdb **全都不同**
> （含 kernel 7.2.6→7.2.7 + trivalent 153→154 那次）；新条件跳过 **0 次**。
> 代价是那 33MB 的节流在 secureblue 上基本不再触发 —— 它几乎每次都重建了某个东西。
> 想强制精确对比加 `--no-fast`（或 workflow_dispatch 勾选 `force`）。

### 退出码

所有子命令**正常运行一律以 0 退出**，无论 verdict 是什么（verdict 从报告、
stdout 或 `--json-out` 的 `verdict.level` 读取）；非零退出码只表示运行出错
（网络/registry/参数错误等）。唯一的显式例外是 `check --fail-on security`：
发现安全修复时以 **10** 退出，专供 CI 使用（本仓库 workflow 的
`FAIL_ON_SECURITY` 变量即依赖它）。

## 测试

`tests/` 包含 **376 项离线回归测试**，不需要网络、不访问 registry
或 Bodhi，也不依赖 `rpm` 二进制或 python `rpm` 模块：

```bash
python3 -m unittest discover -s tests -v
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
| **F** | **secureblue 通知规则**：severity 以 `<severity>` **子元素**（而非属性）发布；Bodhi 原词先经 `severity_updateinfo_str()` 映射成 RHEL 拼写再进 `str2severity`（`urgent→Critical(4)` 触发 `major`、`medium→Moderate(2)` **不弹**、raw Bodhi 词直接进词表一律为 0）；按 Bodhi 原词全链路对拍 + 11 行真值表与上游 `case` 逐条对拍；trivalent 单独升级 ⟹ `major` 且把 verdict 抬到 `update-now`；kernel 靠**包 diff** 识别（`ostree.linux` 相同也要认出来）；kernel 降级不算升级；仅匹配旧构建或未推送的勘误不得触发 |
| **G** | **`no-change` 的判据**：inputhash 相同但包动了 ⟹ 不得判 `no-change`；`--exact 0` 未读版本 ⟹ 也不得判 `no-change`、不得声称"rpmdb 中无变化"；措辞不得再出现"逐字节一致"；`rpmdb_chunk()` 的选层规则必须与 `package_list()` 一致（否则快速路径会校验 A 层却读 B 层） |
| **H** | **报告独立双语排版与决策修正**：报告输出格式改为纯中文在上、`---` 分割、纯英文在下，引入结构化双语处理防止含斜杠说明文本截断；trivalent 将判定从 `consider` 提升至 `update-now` 时剥离冲突的“可合理跳过”文案；`check --fast` 命中相同 rpmdb chunk 时端到端保留无变更确证，正确输出 `no-change` |
| **I** | **勘误附着语义**：剥离 `.secureblue.N` 后的命中要报告（`advisory_corresponding`），但**不得**计入 `has_security_erratum` / 通知预测；精确命中的严重度照旧驱动 `major`；**新增包**上的安全勘误同样驱动预测 |
| **J** | **manifest-only 不得给建议**：`--exact 0` 的 `level` 必须是 `unknown`、并给出 `level_basis`；`no-change` 分支不得吞掉后面的 backlog/告警说明；`silent_important` 不再只看前 60 个重建项 |
| **K** | 静默/致命缺陷：`tag_exists` 只对 404 沉默、其它状态码要告警；backlog 严重度序（`medium` 不得排在 `low` 之后）；Bodhi `nvr=null` 不再崩溃；`coverage_line` 容忍缺键；`group_by_src` 不再要求 `dir`；缺 `ostree.linux` 不再渲染成 `None`；multilib 同名包被记录而非静默丢弃；`read_header` 统计并披露解析失败；报告写入改为原子 |
| **L** | **CI 供应链**：所有 action 钉到 commit SHA；cosign 公钥入库并校验 sha256（运行时不再联网取钥）；`actions: write` 只给需要的 job；`push` 只触发 main；结论为 `unknown` 的运行不再「绿」 |
| **M** | **不得静默截断**：每一处「砍掉一部分」的渲染都必须写明并给出被省略的数量（headline 的源码包/CVE、安全表 CVE 列、已拥有/未推送勘误、增删包列表、backlog 行、chunk 列表、CLI 各列…）；安全表放不下的 CVE 必须有**完整清单**小节，一条不丢；`cves`/`aliases`/`dropped`/`security_pkgs` 等载荷列表**禁止**直接切片；Bodhi 缓存中用于提取 CVE 的 `title`/`notes` 不得先截断（v1 缓存会因此丢 CVE，读到旧格式必须重取）；GITHUB_OUTPUT 输出完整内容并附计数 |
| **O** | **活镜像实测暴露的问题**：带译文的 Summary（I18NSTRING，count>1）不得计为解析失败；`ostree.linux` 变了而 `kernel` 包没变 ⟹ 不得报「内核变化」，报告同时列出 rpmdb 中实际安装的内核；`CVE 2026-114583` 这类非标准拼写必须被识别；新旧更新日志都提到的 CVE 既不算新增也不算丢失；更新日志扫描上限不得在真实更新日志上触发；按 digest 取回的 manifest / config / blob 必须校验 sha256；bearer token 不得随重定向发给其它主机；state 里的基线 digest 被 registry 清理后 `check` 必须回退而不是永久失败；Bodhi 连续失败 3 次即停止查询；`--max-bodhi` 预算优先用于安全敏感包；`check` 清理过期缓存 |

新增的独立回归模块还覆盖：

- `test_signature_policy.py`：缺公钥时强制验证必须失败；history 不得忽略签名选项。
- `test_registry_boundaries.py`：跨 origin 重定向剥离 token；分页只访问原 registry 的 HTTPS origin；相对链接正确解析；畸形 JSON 形状重试后不能继续使用。
- `test_output_boundaries.py`：镜像元数据中的旧分隔符不能覆盖 GITHUB_OUTPUT；随机分隔符碰撞时重选；verdict 只通过环境变量进入 shell。
- `test_legacy_bodhi_cache.py`：无版本缓存必须重取，不能把历史截断的 CVE 数据当完整结果。
- `test_watch_direction.py`：使用状态基线时正确识别 tag 回滚，并保持 JSON、Markdown、CI 输出和新状态一致。
- `test_retained_cves.py`：新增或删除重复提及时，只要保留条目仍提到同一 CVE，就不得声称新增或丢失该编号；保留条目的扫描也有上限并披露。
- `test_bodhi_budget_memo.py`：预算耗尽按源码包和 Fedora release 去重；不把预算缺失写入磁盘，也不反复读取旧缓存。
- `test_digest_integrity.py`：严格校验 `sha256:<64 hex>` 摘要格式，拒绝空摘要、非 sha256 算法或畸形摘要，并在校验失败时清理落盘的临时层文件。
- `test_tar_and_rpmdb_cleanup.py`：解析层 tar 内的相对路径符号链接（只有以 `/` 开头的目标才是绝对路径，不以 `.` 开头的同样相对于链接所在目录），并在 tar 提取或 sqlite 解析异常时清理临时文件。
- `test_errata_and_backlog.py`：新构建的已推送 Bodhi 勘误携带 CVE 时消除更新日志改写造成的假性 CVE 丢失并标记安全属性；`security_backlog` 聚合同一源码包所有落后的 stable 安全勘误（取最新构建、最高严重度与全部 CVE）。
- `test_force_recheck_state.py`：`check --force` 重跑当前构建时复用 `state.json` 中的 `prev_digest` 基线并保持回滚方向；读回的基线标签保持原样，不会被截成带省略说明的残段。
- `test_rpm_header_tags.py`：Vendor / License 取自各自的头部标签（1011 / 1014）；1010 是 Distribution，不得当作 vendor。
- `test_token_realm.py`：pull token 的 realm 只接受 http(s)；`file:`、`ftp:`、`data:` 等 realm 不得被打开。
- `test_passed_over_errata.py`：被本次更新越过的中间构建（旧 < 构建 ≤ 新，且与旧构建同属一个 Fedora 版本）的 stable 安全勘误计入结论与 CVE，但不计入通知预测；范围之外、未推送、非安全类勘误、降级以及跨 Fedora 版本的构建都不计。
- `test_baseline_label.py`：来自状态文件的基线标签带上构建时间（`版本 @ 时间`），同一天内共用版本号的多次构建不再显示成 `X -> latest (X)`。
- `test_dropped_cves_wording.py`：新版更新日志不再提及的 CVE 编号只按「不再提及」呈现，小节标题与依据文本不得再写成「本次更新移除的修复」。
- `test_registry_auth_hint.py`：registry 返回 401/403 时指出最可能的原因（仓库不存在或非公开，检查 `--image`）；其它状态码不带该提示。
- `test_cache_write.py`：缓存文件经一次性 JSON 编码器写出，不走逐段迭代的 `json.dump()`。
- `test_downgrade_reverted_erratum.py`：降级被点名「回退」的，是被离开的那个构建的已发布安全勘误；降级目标自己的勘误、非安全类或未推送的勘误都不得被说成被回退。
- `test_evidence_label.py`：只因非 security 类勘误（列出 CVE 或高严重度）而判为安全相关的源码包，`security_basis` 与 headline 不得写成「更新日志 CVE」；新版更新日志真有 CVE 时照旧。
- `test_since_last_look_note.py`：「上次查看之后还推送了 N 次构建」只在基线就是上次分析的镜像时提示；显式 `--a` 的对比不得被说成「你的上一版镜像 -> 当前镜像」。
- `test_bodhi_cache_key.py`：只差标点的源码包名（`foo-bar` / `foo_bar` / `foo.bar` …）各用各的 Bodhi 缓存文件，一个包的勘误不得被当成另一个包的返回。
- `test_bodhi_cache_prune.py`：过了 TTL 的 Bodhi 应答在清理时即被删除，同龄的 pkglist 仍按 `--prune-days` 保留；`0` 依旧全部保留。
- `test_history_baseline_label.py`：取自构建历史的基线与状态文件同样标注为「版本 @ 时间」，缺版本注解的构建不再标成 `None @ …`。
- `test_cache_tmp_prune.py`：运行被中途杀掉时留下的 `<缓存文件>.json.tmp.<pid>` 满一小时即被清理；仍在写入的临时文件和非缓存文件不动。
- `test_json_size_cap.py`：manifest / 镜像 config / tag 页这类整体载入内存解析的 JSON 文档上限为 16 MiB，不再沿用 200 MiB 的 blob 上限；token 应答同样有界，超限按获取失败处理。
- `test_malformed_manifest.py`：registry 返回 200 但内容不是 manifest（错误页、缺 `size` 的层、非数字的 stability…）时报出带说明的 registry 错误而不是 traceback；history 扫描把它记为 `malformed manifest`，不再说成网络错误。
- `test_bodhi_retry.py`：偶发失败的 Bodhi 查询会再试一次（同样计入 `--max-bodhi`），单次超时不再造成「勘误覆盖不完整」；连续失败期间和预算用尽后不重试。
- `test_tag_list_page_budget.py`：tag 列表默认最多读 100 页；ghcr 按从旧到新列出，超过 12 页的仓库仍必须看得到最新的 tag。
- `test_rpm_header_blob_type.py`：`Packages` 表中 blob 为 NULL、文本或数字的行计为被拒头部并在报告中披露，不再让整次运行崩溃。

其中 A6 的向量取自 rpm 上游 `tests/rpmvercmp.at`，已抓取为
`tests/rpmvercmp_vectors.json`，因此**离线也能验证**与 rpm 本体的一致性。

CI 中由 `test` 作业运行；`watch` 作业**不**依赖 `test`（两者并行）——测试失败
不会阻塞每小时的监控，但会在 Tests 作业中红牌示警。

## GitHub Action

仓库自带 `.github/workflows/sbwatch.yml`，由 [worker-cron](https://github.com/lingyicute/worker-cron) 驱动，每半小时就会跑一次：

- cache `~/.cache/sbwatch` (pkglist + Bodhi + state.json)，按 image+arch 分命名空间，
  并有一个 prune 步骤只保留最近 7 份（否则 `state.json` 会被 LRU 挤掉，`check` 就失去基线）；
  结论为 `no-update` 的运行不再重复保存缓存（该路径不往缓存目录写任何东西）
- `check` 分析完成后会删除超过 14 天的 pkglist 缓存文件（刚对比的两个镜像除外；
  `--prune-days N` 调整，`0` 关闭）：每个分析过的构建会留下约 11 MB 的 pkglist，
  而整个缓存目录每次运行都会被整体恢复、保存；Bodhi 应答过了 6 小时 TTL 就再也不会
  被读取，清理时直接删除，不再陪跑 14 天；运行被中途杀掉时留下的
  `*.json.tmp.<pid>` 临时文件满一小时也一并清理
- `sbwatch.py check` → `report.md` + `report.md.json` → summary + artifact
  （workflow 不传 `--exact` / `--no-fast`，所以走默认值：`--exact 1` + `--fast` 开启，
  见上文「`check --fast` 与 manifest-only」）
- 若 verdict 是 `update-now`/`consider`（`skip` 仅在 `POST_SKIP_VERDICT=true` 时），会评论到
  标题恰为 `secureblue update watch` 的 sticky issue（GitHub 评论上限 65536 字符，
  超长报告会被截断并注明，完整报告见 run summary / artifact）
- **结论为 `unknown` 的运行会失败**（红色）：`unknown` 意味着"没得出结论"
  （没有可比基线、registry 探测失败等）。过去它和"这周很安静"长得一模一样，
  监控悄悄失效也发现不了。报告仍会照常上传为 artifact
- cosign 公钥 `cosign.pub` **入库**并校验 sha256（`COSIGN_PUB_SHA256`），
  运行时不再从网络取钥；上游换钥会在这里失败，而不是静默改变"已验证"的含义
- 若配置了 `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` secrets，推送到 Telegram
  （Telegram 单条消息上限 4096 字符，超出部分会被截断并注明，完整报告见 run summary）

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
