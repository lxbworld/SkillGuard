# SkillGuard — Competitive Analysis

调研日期：2026-10-07。所有结论均基于公开仓库、文档与官网内容。

---

## 0. 一句话结论

**「Skill 的 npm + npm audit + package-lock」这个整体方向没有人完整做过**，
但其中**每一块都已被单点覆盖**，且已有项目（skil-lock）把「capability lockfile + policy + 审批流」
做成了完整产品。SkillGuard 不能以「我有 lockfile / 有 policy / 有 scanner」为卖点。

差异化必须落在三处：

1. **Declared vs Observed（权限声明的验证）** —— 目前无人做生产级实现。
2. **确定性、离线、无网络的单二进制（Rust）** —— 现有方案要么依赖云端 LLM（Snyk），要么依赖 Node/Python 运行时。
3. **Package 生命周期整链** —— 现有项目的重资产在 registry / 发现 / 生态，安装只是附带。

---

## 1. 竞品矩阵

| 项目 | 语言/形态 | 核心定位 | Lockfile | Policy | Scanner | Provenance | 需要联网/LLM | License |
|---|---|---|---|---|---|---|---|---|
| **Snyk Agent Scan** | Python, uvx/二进制 | 机器级发现 + 威胁分析 | ❌ | ❌（企业 MDM） | ✅ 14 类风险 | ❌ | **✅ 云端分析 API** | Apache-2.0 |
| **skillmds / SkillMD** | Node/TS, npm | 1.13M skill 的 registry + lint | ✅ pinned commit | ❌ | ✅ 能力 flags（deterministic） | ✅ commit pin | ❌（本地） | MIT |
| **skill-preflight** | Node, npx | 安装前 scorecard | ❌ | ✅ JSON policy + fail-on | ✅ 100 分制 | ❌ | ❌ | MIT |
| **SkillSpector (NVIDIA)** | Python + uv | 扫描器（Tier 1） | ❌ | ✅ triage 表 | ✅ 静态 + 可选 LLM | ❌ | 可选 | 见仓库 |
| **skills (vercel-labs, skills.sh)** | Node, npx | 生态级安装器 + 排行榜 | ✅ skills-lock.json | ❌ | ❌ | ✅ hash/folder hash | 部分 | MIT |
| **skil-lock** | Go | **能力面锁定 + PR 审批** | ✅ skills.lock (SPEC) | ✅ YAML + 审批 | ✅ | ✅ content_hash | ❌ | Apache-2.0 |
| **skillpkg/spm** | Go + 前端 | 私有 registry + Sigstore 签名 | ✅ skills-lock.json | ❌ | ✅ 3 层 | ✅ Sigstore | ✅ registry | MIT |
| **skillpm** | Node | npm 原生包管理器 | ✅ 复用 npm | ❌ | 扫描 node_modules 找 skill | ✅ npm | ✅ npm | MIT |
| **skills-package-manager** | Node | 单文件 manifest 固定 commit | ✅ skills.json | ❌ | ❌ | ✅ commit | ❌ | 见仓库 |
| **skill** (crates.io) | **Rust 库** | Skill 生态嵌入框架 | ✅ 双 lockfile | ❌ | ❌ | ✅ | 部分 | 见 crates.io |
| **AgentBound / SkillGuard (arXiv)** | 学术 | 权限框架 + 运行时强制 | ✅ manifest | ✅ | — | — | 需要沙箱 | 论文 |

> ⚠️ **命名冲突警告**：arXiv `2606.03024` 已提出 **SkillGuard: A Permission Framework for Agent Skills**
> （Android 式权限 manifest，91.0% F1 manifest 生成）。另有一篇 `2605.10990` 的同名系统做 skill drift 监控。
> 本仓库名称与其撞名。建议保留 SkillGuard 但**必须在 README 明确引用并区分**这两篇论文，避免被误认为官方实现。

---

## 2. 各项目能力细评

### 2.1 Snyk Agent Scan

- **强项**：威胁研究深（4000 skill 语料分析）、14 类风险、MCP + Skill 双覆盖、MDM 后台扫描、CI 模式。
- **致命处（对我方有利）**：`--analysis-url` 指向 Snyk 分析 API。**它是云端 LLM 驱动的**，本地不产生 verdict。
  官方反复声明 CLI 输出「experimental、可能随时变更」，不推荐生产依赖其 issue code。
- **对我方的启示**：离线确定性扫描是一个真实且未被占据的位置。企业对「上传 Skill 到第三方」也有天然顾虑。

### 2.2 skillmds / SkillMD

- **强项**：规模（1.13M skills）、8 条 lint 规则、capability scanner 明确「deterministic、无需模型、单文件 <1s」、
  MCP server、GitHub Action、SARIF。**开源可读规则**，这一点很聪明。
- **它自己的短板**：官网自曝 860,246 skill 中仅 51.9% 有能力 flags、4.5% 有第三方扫描结果。
  `add` 是「lint first, never executes scripts」——**scan 不是 install 的阻断门**，没有 policy 阻断。
- **对我方的启示**：capability flags ≠ permissions 声明校验。它有 flags，无 declared-vs-observed diff。

### 2.3 skill-preflight

- **强项**：policy（`failBelow` / `failOn` / `ignoreRules` / `exclude`）、SARIF、GitHub Action、`--installed` 发现、
  benchmark 方法论公开、附带 companion skill 给 agent 用。
- **短板**：核心产出是**一个分数**。文档明确反对复制 scorecard，我们也不应复制。
  无 lockfile、无 provenance、无 install。

### 2.4 skil-lock —— 这是最需要警惕的对手

**Apache-2.0 / Go。它已经把「能力面锁 + 策略 + 审批 + CI 门」做完了**：

- `skills.lock` 记录 `shell_commands` / `network_urls` / `file_reads` / `file_writes` / `allowed_tools` /
  `bundled_scripts` + 每个文件的 `script_hashes`。
- `.skil-lock.yaml` 策略（protected_paths / allowed_domains / 分级 severity）。
- `.skil-lock-approvals.yaml` 审批审计（reviewer + reason + 时间戳，可 PR 级作用域，防止「批准后重引入」）。
- `skil-lock ci` 输出 PR 评论 + SARIF，`skil-lock diff` 对比两次快照。
- 有正式 SPEC.md（v0.1, CC BY 4.0）。
- 它自己的对比表直接点名 Snyk Agent Scan 和 Mondoo Skills Check 为「pre-install scanner」。

**它没做的**：
1. **Declared vs Observed**：只记录 observed，**不校验 Skill 自己声明的 permissions**。
2. **内容寻址的来源证明**：content_hash 只做漂移检测，不做 source+commit+digest 三元绑定。
3. **安装器**：它是 post-install PR 工作流，不是 package manager。
4. **生态**：不负责把 skill 装进各个 agent 目录。

### 2.5 vercel-labs/skills（npm `skills`，周下载 724 万）

- **强项**：生态事实标准，72+ agent，`.skill-lock.json`（全局）+ `skills-lock.json`（项目，含 `computedHash`、
  GitHub tree SHA folder hash）、MCP server。
- **短板**：**完全无安全维度**。这是最大的机会——最大装机量的安装器没有任何 policy 阻断。
- 已知 bug：本地源在 lockfile 里写绝对路径（issue #561），跨机器不可复现。

### 2.6 skillpkg/spm

- 3 层安全扫描 + **Sigstore 签名** + 私有 registry。
- 证明「签名 + registry」这条路可行，但它是 **registry-first**，与「local-first」定位冲突，
  且需要信任 skillpkg.dev。

### 2.7 crates.io 的 `skill` crate

已存在 Rust 实现（v0.8.3），提供 discovery/install/lockfile/provider/sanitize。
**不是安全工具**。但它说明「Rust + Skill」这条路技术上完全通顺，且我们有潜在的复用/互操作空间。

---

## 3. 能力覆盖 vs 我们的目标

需求文档定义的 6 项能力，逐项归属：

| 能力 | 已被谁做 | 是否空缺 |
|---|---|---|
| Package Management | skills, skillpm, spm | ❌ 不空缺 |
| Scan | Snyk, SkillMD, preflight, SkillSpector | ❌ 不空缺 |
| Provenance | skills (hash), spm (Sigstore) | ⚠️ 部分空缺（无统一三元绑定） |
| Lockfile | skills, skills-lock, skil-lock | ❌ 不空缺 |
| Policy | skil-lock, preflight, AgentBound(论文) | ⚠️ 部分空缺（policy≠permission 校验） |
| **Capability 声明验证（Declared vs Observed）** | **仅 arXiv SkillGuard 论文** | ✅ **真空缺** |
| **离线确定性全链（scan+policy+install 一次跑完）** | **无** | ✅ **真空缺** |
| **跨 scanner 组合 / 统一 evidence 模型** | SkillMD 存第三方结果，但无组合 | ✅ **真空缺** |

---

## 4. 真正未被解决的三个问题（我们的立足点）

### 问题 1：Skill 声明的 permissions 从未被验证

Android 的核心洞察是 **manifest 是可被系统校验的契约**。目前所有工具：
- 要么只观察（observed），要么只读声明但不校验。
- **没有任何工具回答：「这个 Skill 声明了 `network: api.example.com`，但代码里还访问了 `evil.example.com`，因此拒绝安装。」**

这是我们 Phase 2 的核心，也是护城河。学术界的 SkillGuard 用 LLM 生成 manifest（91% F1），
我们用**确定性推导 + 显式声明 + 差分**，零 LLM。

### 问题 2：观察是离散的，阻断是缺席的

- skil-lock 在 PR 时阻断，但 skill 已经装到机器上了。
- skills / skillpm 装的时候不阻断，扫描是事后独立命令。
- **没有任何工具把 `scan → policy → block/approve → install` 做成一次原子的、有锁文件支撑的流程。**

需求文档 §5 的 `agentpkg add github:user/financial-analysis` 体验，业界没有等价物。

### 问题 3：可复现安装的完整闭环缺失

`skills-lock.json` 有 hash 但没有 commit（skillpm 文档提到 `package-lock.json` 是 npm 的真相，
skill 追踪在 `skills-lock.json`）；skills-lock 有 commit 但无 policy。**没有一个 lockfile 同时包含：
source + commit + content digest + declared permissions + observed capabilities + policy decision。**

---

## 5. 与「SkillGuard (arXiv)」的关系 —— 诚实处理

那篇论文做的事：Skill Manifest + baseline policy + session state + 运行时强制（需要沙箱），
用 315 个真实 skill 验证权限分类法 99.76% 覆盖、manifest 自动生成 91.0% F1。

**我们与它的关系应该是互补，不是竞争**：
- 它在 **runtime enforcement**（需要 sandbox，我们明确不做）。
- 我们在 **pre-install verification**（不需要 sandbox，可离线，符合 local-first）。

建议：在 README 与论文互相引用，明确「本项目是 SkillGuard 论文 permission manifest 思想的
pre-install、无 LLM、纯静态实现」。这比抢名字更能建立可信度，也避免撞名的尴尬。

---

## 6. 差异化定位（一句话，可直接用于 README）

> SkillGuard 是 **Skill 生态的包管理器 + 信任层**：
> 它是**唯一**一个在**安装前**就把 **declared permissions 与 observed capabilities 做差分**、
> 并用**声明式 policy + 审批锁文件**阻断安装的工具；
> 核心判断**完全确定性、离线完成、单 Rust 二进制、无 LLM、无云端**。

对标关系一句话版：
- 不是 Snyk（我们离线、不上传、阻断安装）
- 不是 SkillMD（我们不是 registry，我们有 policy 阻断和锁文件）
- 不是 skil-lock（我们多 declared-vs-observed、多安装、多来源证明）
- 不是 skills/spm（他们不管安全，我们不管生态）

---

## 7. 风险与止损点

| 风险 | 应对 |
|---|---|
| skil-lock 快速补上 declared-vs-observed | 先发论文/规范占位；spec 先行，做 `SKILLGUARD.lock` spec 草案并 CC BY 发布 |
| arXiv SkillGuard 抢名 | 主动引用 + 声明互补；考虑用产品名区分（文档见 MVP.md「命名」一节） |
| 生态锁定在 skills（7M/周） | 提供 `skills-lock.json` → `SKILLGUARD.lock` 的**读取与迁移**，做补充而非替代 |
| 「又一个 skill linter」误读 | 首屏 demo 必须是 `add → 扫描 → policy 阻断 → approve → 锁文件`，不是 `lint` |
| Rust 生态缺 tree-sitter 绑定成熟度 | MVP 先用 regex + YAML/JSON parser（确定性已足够），tree-sitter 作为可选增强 |

**止损条件**：若 Phase 2（declared-vs-observed）无法在确定性下达到可接受的 precision，
退回 Phase 1 做「最好用的离线 evidence-grade scanner + policy 阻断」，仍构成独立产品。