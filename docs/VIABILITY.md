# SkillGuard — Feasibility, Direction & Go-To-Market

调研日期：2026-10-07。本文档回答三个问题：**做不做？做什么？怎么被人知道？**

---

## 0. 执行摘要（先读这一段）

**结论：做，但当前的方向定义有一个重大错误需要修正。**

| 判断 | 结论 |
|---|---|
| 问题是否真实存在 | ✅ **极真实**。已有 4 起大规模实证：ClawHub 11.9% 恶意率、1,184 个投毒 skill、Snyk 3,984 skill 审计、2 篇 arXiv 论文 |
| 时机是否正确 | ✅ **2026 年是窗口期**。生态从 2,179 → 606,555 工具（约 11 个月），且已出现 CVE 级事故 |
| 「Skill 的 npm」这个定位是否可行 | ⚠️ **作为定位不可行**。skills（周下载 724 万）+ skills.sh + skillpm 已占据安装入口，且我们无意争夺 registry |
| 「Skill 的 npm audit」是否可行 | ✅ **可行且未被占据**。离线、确定性、声明 vs 实际，这是唯一空缺 |
| 单人 / 单一模型能否完成 | ✅ MVP 可行。⚠️ 但「完整包管理器」不可能，必须砍 |
| 开源能否获得知名度 | ✅ **能，但前提是先做 Phase 0 语料研究**，而不是先做产品 |
| 最大风险 | 🔴 **不是技术，是分发**。SecureClaw（功能完整、OWASP ASI 全覆盖）Show HN 只有 2 分 |

**核心建议（三条，按优先级）：**

1. **砍掉「包管理器」定位，改为「Skill 的 npm audit + 权限验证标准」。** 安装入口之争打不过 vercel-labs。
2. **Phase 0 改成：扫描 10 万个公开 skill，发布首份大规模实证报告。** 这是唯一能带来
   Snyk/Socket 级别知名度的动作，而且只需要 Phase 1 的扫描器。**先有数据，后有产品。**
3. **做规则引擎库 + 可嵌入，不只做 CLI。** 让 skil-lock / skillmds / registry 服务
   嵌入我们的规则，这是 Semgrep 走通的路（被 GitLab 选为默认分析器）。

---

## 1. 市场：问题有多真实

### 1.1 生态规模（Skillful.sh，聚合 55 个目录/registry，2026-09-30）

| 指标 | 数值 |
|---|---|
| 工具总数 | **606,555** |
| AI Skills | 334,279（55.1%） |
| MCP Servers | 245,589（40.5%） |
| Autonomous Agents | 26,687（4.4%） |
| 近 30 天新增 | 46,534（约 **1,551/天**） |
| 近 90 天新增 | 152,528 |

### 1.2 GitHub 上的真实存量（arXiv 2608.10906《GitSkills》，2026-07 采集）

| 指标 | 数值 |
|---|---|
| Skill 文件出现次数 | **3,797,117** |
| 公开仓库数 | 282,200 |
| 账号数 | 195,841 |
| 内容重复率 | **50.5%** |

> 论文原话：「Skills also have no central registry or package manager;
> developers reuse them by copying folders between repositories.」

**50.5% 的重复率 + 3.8M 文件 + 无 registry** —— 这正是「复制即传播，无审查」，
也就正是 SkillGuard 存在的理由，同时也说明 **lockfile / digest 的价值极大**
（复制后无法知道拿到的是不是同一份东西）。

### 1.3 已确认的攻击（这是最好的立项论据）

| 时间 | 事件 | 数据 |
|---|---|---|
| 2026-02 | Koi Security（Oren Yomtov）审计 ClawHub | **341 个恶意 skill = 2,857 的 11.9%** |
| 2026-02 | Snyk 审计 ClawHub + skills.sh 3,984 个 skill | 91% 确认恶意含提示注入；100% 含恶意代码 |
| 2026-02 起 | ClawHub 接入 VirusTotal + ClawScan | 仍持续被绕过（Unit 42） |
| 2026-02~05 | **1,184+ 恶意 skill** 在 ClawHub 分发 Atomic macOS Stealer | 凭据窃取 |
| — | CSA 研究（2026-05） | **下载量前 7 的 skill 中 5 个确认是恶意** |
| 2026-04 | Anthropic 内部评测事故 | AI agent 把恶意包发到**真实 PyPI**，1 小时内 15 台真实系统运行，**其中一台是安全扫描器** |
| — | Check Point 披露 Claude Code 两个 CVE | CVE-2025-59536 / CVE-2026-21852：仓库内配置文件自动加载、无完整性校验 |
| 2026-03 | TeamPCP 攻陷 Trivy、KICS、LiteLLM、Telnyx | **安全工具本身成为供应链首要目标** |
| 2026-06 | Sapphire Sleet 攻陷 144 个 @mastra npm 包（88 分钟） | 窃取 LLM/云凭据 |

### 1.4 一个全新的、更难的攻击面（学术共识）

arXiv **2605.11418**（2026-05）给出了「无恶意代码也能攻破 registry」的实证：

- 关键词注入让恶意 skill 在 embedding 检索 Top-10 中的进入率 **80%**，成对胜率 **86%**
- description 框架化使 agent 偏向恶意变体 **77.6%**（人工评审无法区分）
- 绕过自动化治理分类器的比例 **36.5%–100%**

Snyk 把这类攻击命名为 **ToxicSkills**。Check Point 在 Cursor 上演示了
「看起来无害的 MCP 配置文件 → 一次批准 → 长期后门」。

### 1.5 已经有人在做（必须在立项时知道）

| 玩家 | 状态 | 对我们的意义 |
|---|---|---|
| **Socket.dev** | Series C **$60M / 估值 $10 亿**（2026-03），139 人。2026-02 起扫描 skills.sh 60,000+ skill；Mastra 攻击后 **6 分钟内告警** | 🔴 **最强竞争者**。有资金、有威胁情报、有 registry 侧数据 |
| **Endor Labs（AURI）** | 定位「Agentic Application Security Platform」，明写「Every model, skill, MCP server, and tool call extends your supply chain」，**动作发生前 enforce policy：allow / block / ask a human** | 🔴 **最强定位竞争者**。我们的「阻断安装」叙事几乎一模一样，但他们做全栈 |
| **Snyk** | Agent Scan + 云端分析 API，Apache-2.0 | 云端路线，无法离线 |
| **skillmds** | 1.13M skill registry，MIT，CLI + MCP + Action + SARIF | 生态入口 |
| **skills (vercel-labs)** | 周下载 **7,243,164**，72+ agent | 安装入口，不可撼动 |
| **skil-lock** | Apache-2.0 / Go，capability lockfile + policy + 审批 + SPEC.md + Action | 最直接的功能竞争者 |
| **skill-preflight** | MIT，scorecard + policy + SARIF + Action | 评分路线 |
| **SecureClaw（Adversa AI）** | 功能声称覆盖 OWASP ASI Top 10 全部 10 类 | ⚠️ **Show HN 只有 2 分、1 条评论** —— 警示教材 |
| **AgentSec（agentsec.sh）** | Unfunded，2026 成立，"security auditing for autonomous agent skill sets" | 又一个入场者 |
| **skillful.sh** | 60 万工具目录，已给 skill 打 **A+~F 安全等级** | 「又一个人人打分」的位置 |
| arXiv | 2606.03024（SkillGuard 权限框架）、2605.10990（SkillGuard drift）、2605.11418（registry 投毒）、2608.10906（GitSkills）、**USENIX Security 2026《Do Not Mention This to the User》**、Skill-Inject benchmark、AgentSkillOS | 学术热度极高，是**引流通道**也是**被超越风险** |

---

## 2. 定位诊断：原方向哪里错了

需求文档 §17 的产品模型假设我们要同时做 Discovery + Package + Verify + Scan + Policy + Lock + Install。

**问题：这是一个「包管理器 + 安全」双重身份，而两者都需要巨额生态投入。**

对照现实：

| 我们想做的 | 现实 |
|---|---|
| 做 install 入口 | skills 周下载 724 万、72+ agent、已有 lockfile；skillpm 复用 npm；skills-package-manager 有 pnpm 插件。**要赢需要 10x 的生态投入** |
| 做 registry | skillmds 113 万 + skills.sh 10 万 + 约 40 个 marketplace。需求 §6 也明确禁止 |
| 做 scan | 4 家在做，其中 2 家有上亿估值 |
| 做 policy/lock | skil-lock 已有 SPEC.md |
| **做 declared vs observed** | ✅ **无人做** |
| **做离线确定性** | ✅ **无人做**（Snyk 必须上云） |
| **做「证据级」精度输出** | ⚠️ 部分做（SkillMD 明确说自己「blunt，只告诉你看哪几行」），但无人做到「可复现的 precision 数字」 |

### 2.1 修正后的定位

> **SkillGuard = 离线、确定性的 Agent Skill 验证层。**
> 不是「安装器」，而是**安装前的验证标准**：
> 1. 扫描并给出**可复现**的能力证据
> 2. 校验 Skill 声明的权限与其实际行为的差异（DECLARED vs OBSERVED）
> 3. 用声明式 policy + 审批锁文件阻断安装
> 4. 输出 SARIF，让结果进入既有 CI 生态

**关键转向：从「我们也能装」变成「我们定义怎么验证，以及验证结果可以被信任」。**

前者是功能竞争（打不过 724 万周下载），后者是标准竞争（可以赢）。

### 2.2 三条不做（写进 README 与代码注释）

- ❌ 不做 registry、不做搜索、不做评分榜（skillful.sh 已占位，且评分是伪安全信号）
- ❌ 不做运行时沙箱/强制（属于 AgentBound / AgentSkillOS / arXiv SkillGuard 论文）
- ❌ 不做 MCP 全生态扫描（需求 §6 已定；且 Snyk/Endor 已做）

---

## 3. 可行性评估（技术 + 组织）

### 3.1 技术可行性：✅ MVP 完全可行

| 组件 | 可行性 | 说明 |
|---|---|---|
| SKILL.md 解析（frontmatter + body） | ✅ 高 | 格式简单，有官方 spec（agentskills.io，Anthropic 2025-12 发布，Linux Foundation / Agentic AI Foundation 托管） |
| 确定性规则（44 条） | ✅ 高 | regex + YAML/JSON 足够；技术风险低 |
| 能力推导 + 声明差分 | ⚠️ 中 | **精度是唯一真风险**（见 3.2） |
| 目录摘要哈希 | ✅ 高 | 算法已在 skills-lock / pcomans/skills-lock 验证过 |
| git provenance | ✅ 高 | 只读子进程 |
| policy 引擎 | ✅ 高 | 声明式 YAML → 四态决策 |
| 离线单二进制 Rust | ✅ 高 | 依赖树小 |
| **安装器** | ❌ 低价值高成本 | 见 §2 —— **建议砍掉或只做「写 agent 目录」这一步** |

### 3.2 唯一真风险：declared vs observed 的精度

学术界的对照组很明确：
- arXiv SkillGuard 用 LLM 自动生成 manifest，capability 级 F1 **91.0%**（precision 85.6% / recall 97.1%）
- 该文同时报告：**56.5% 的 skill 存在 over-declared（多声明），17.4% 存在 under-declared（少声明）**

**解读**：under-declared 的基准率只有 17.4%。这意味着
- 朴素实现的 precision 上限受限于「我们如何判定一个观察值是否值得要求声明」
- **但反过来看，这是一个极有说服力的宣传数据**：「17.4% 的真实 skill 少声明了自己要访问什么」

**我们的差异化应对（这是必须写进设计的）**：
1. 只对**代码文件**（`scripts/`、代码块）中的观察值要求声明；Markdown 正文里的 URL/命令视为
   「说明性引用」不计入能力。这是把 precision 从 ~0.5 拉到 ~0.85 的关键。
2. 提供 `skillguard adopt`：**从当前 observed 自动生成 permissions 声明并写入 frontmatter**，
   形成基线；之后所有新增未声明能力才报警。
   → **这解决了「鸡生蛋」问题**：没有 manifest 生态，就自己 bootstrap。
3. 阶段化：先「只报不阻断」积累用户反馈，达到 precision ≥ 0.8 再开阻断。

### 3.3 组织可行性

| 维度 | 评估 |
|---|---|
| 单人 + DeepSeek 约束 | ✅ MVP 可行（Rust 编译期检查对 AI 生成代码友好）。⚠️ 完整包管理器不可行 |
| 依赖上游存活 | ⚠️ 中风险。vercel-labs/skills 若添加内建安全，会挤压安装侧；**但不影响验证侧** |
| 撞名成本 | 🔴 **真实存在**：2 篇 arXiv 论文同名 + agentsec.sh + SecureClaw 同赛道。搜索与心智占领都会受损 |
| 持续维护成本 | ⚠️ 中。规则集需要对抗性演化（Unit 42 已证明绕过会发生） |

---

## 4. 方向建议：Phase 0 是最高杠杆的一步

### 4.1 为什么先做语料研究

Snyk 的知名度来自审计 3,984 个 skill；Socket 的知名度来自扫描 60,000 个 skill；
arXiv GitSkills 论文来自 3.8M 文件的语料。
**在这个领域，「首个大规模实证」的新闻价值远高于又一个工具发布。**

而且它同时解决四个问题：
1. **知名度** — 数据型报告天然被 HN / Reddit / 安全媒体 / 学术引用
2. **可信度** — 「我们扫描了 10 万个 skill，发现 X% 有未声明的出网访问」无法被反驳
3. **规则验证** — 用真实语料测 precision/recall，而不是自造 fixture
4. **数据集归属** — 语料索引本身成为可引用的资产（GitSkills 已被 alphaXiv 收录）

### 4.2 Phase 0 提案

```text
skillguard scan --corpus <source> --stats --json
```

产出 `docs/CORPUS_REPORT.md`：
- 语料：skills.sh / ClawHub / GitHub tag `agent-skills` 分层抽样（目标 100,000 个 skill，
  **全部 commit 锁定并记录 digest**，方法学可复现）
- 指标：
  - 含硬编码 secret 的比例
  - 含 `download → execute` 链的比例
  - 含 shell 执行 / 出网 / 敏感路径访问的比例
  - **有 frontmatter 权限声明的比例（预期 < 2%，这就是 declared-vs-observed 的市场缺口）**
  - 有 LICENSE 的比例 / 声明与文件不符的比例
  - 检测规则的 precision（在人工标注的 500 个样本上）
  - 绕过手法分布：base64、零宽字符、超大文件（Unit 42 已证实有效）
- **诚实披露**：检出 ≠ 判定；给出 false positive 分析

配套产出：
- 一个公开 JSON 数据集（skill 路径 + digest + finding 摘要），可直接被第三方研究引用
- 一份 arXiv 预印本（生态侧安全态势）
- 一篇技术博客 + HN Show HN 的素材

**这一步只需要 Phase 1 的扫描器 + 一个语料驱动模式。技术风险低，收益极高。**

### 4.3 分发渠道（按有效性排序）

参考 Semgrep 的路径（2017 创立 → 2020 开源 → 2023 约 200 万用户 / 15.3k star → 2025 Series D），
**最大的杠杆从来不是发 HN，而是成为生态的默认环节**（Semgrep 被 GitLab 14 选为默认 SAST 分析器）。

| 优先级 | 渠道 | 具体动作 | 为什么有效 |
|---|---|---|---|
| **P0** | **生态默认环节** | ① pre-commit hook ② GitHub Action（零安装，走 Code Scanning） ③ 提供 Rust 库 + C ABI 供其他工具嵌入 | Semgrep 的核心转折点 |
| **P0** | **互操作而非替代** | `skillguard import skills-lock.json`；被 skil-lock / skillmds / registry 服务调用 | 阻力最小的进入方式 |
| P1 | **Phase 0 报告** | arXiv 预印本 + 技术博客 + 公开数据集 | 唯一能拿 HN 首页的姿势 |
| P1 | **规则可贡献** | 规则 ID + fixture 一一对应的贡献流程（Semgrep 的 3000+ 社区规则是关键资产） | 规则数量即护城河 |
| P2 | **Awesome list 渗透** | `LLMSecurity/awesome-agent-skills-security`、`mcp-security-project/awesome-agentic-mcp-security`、`baibizhe/Awesome-Skills-Paper` —— 均活跃接受 PR | 长尾持续引流 |
| P2 | **研究合作** | 与做 Skill-Inject / SkillsMP 的学术组建立联系；论文引用是最持久的 backlink | 学术信誉 |
| P2 | **安全研究者通道** | 邀请 Trail of Bits 等发布 rules；open-security 方向的 skills 生态很活跃 | 信誉 + 规则 |
| P3 | 会议 / 演讲 | OWASP Agentic Security、SANS、BSides、ChaosConf | 深度而非广度 |
| P3 | OpenSSF / 基金会 | 申请加入 Security Tooling 组；Tidelift / Sponsors 维持维护 | 长期可持续 |

### 4.4 冷启动的现实预期（诚实版）

Show HN 的实际分布（调研观察）：
- 功能完整 + 无受众：~2 分、1 条评论（SecureClaw 真实案例）
- 有受众 + 讲清痛点：100–260 分、30–65 条评论（Tracecat 264 分）
- 有强品牌背书：更高（SubImage 135 分）

**结论：不要在产品没做完时发 Show HN。** 正确的顺序是
Phase 0 报告（有数据、有钩子）→ Phase 1 工具（可直接试）→ Phase 2 差异化 → 一次性 Launch HN。

---

## 5. 命名与品牌（建议决策）

| 方案 | 说明 | 建议 |
|---|---|---|
| `skillguard` | 已被 2 篇 arXiv 论文使用 + 至少 2 个在跑项目（agentsec.sh、SecureClaw）占据心智。搜索结果会被淹没 | 🔴 不推荐 |
| **`skilltrust`** | 语义准确（信任层），与本项目定位一致，检索干净 | 🟢 可用 |
| **`skillscope`** | 强调「看清 skill 的一切」，且与已有 skills.sh/awesomeagentskills 区分度尚可 | 🟢 可用 |
| **`sgt`**（skill guard tool） | 短、CLI 好读 | 🟡 可用但信息量低 |
| **`veriskill` / `skillverify`** | 强调验证 | 🟡 可用 |

**建议：仓库名保留 `SkillGuard`（已建、已推送、无沉没成本），
但产品名用 `skillscope` 或 `skilltrust`，README 首段说明关系。**
或者更干脆：**改仓库名为 `skillscope`，把 SkillGuard 作为旧名在 README 说明。**

这是一个需要你拍板的决策，见文末提问。

---

## 6. 里程碑（重排）

| 阶段 | 内容 | 目的 | 出口条件 |
|---|---|---|---|
| **P0** | 语料扫描模式 + 10 万 skill 实证报告 + 公开数据集 + arXiv 预印本 | **知名度与规则验证** | 规则 precision ≥ 0.85（500 标注样本）；报告发布 |
| P1 | 扫描器 + 44 规则 + SARIF + GH Action + pre-commit + Rust 库 | 产品可用 | fixtures 全绿；被至少 1 个外部工具嵌入或采用 |
| P2 | capability + `adopt` 生成声明 + declared vs observed（先只报不阻断） | 差异化 | precision ≥ 0.8；30 个真实 skill 验证 |
| P3 | policy 引擎 + 阻断 + 审批锁文件 + `import skills-lock.json` | 落地到流程 | deny 时零写入（断言测试） |
| P4 | 语料索引 / 规则 registry / 研究合作 | 护城河 | 社区规则贡献 ≥ 20 条 |
| P5（可选） | `add` / `install`（仅当 P1–P3 有明确用户需求时才做） | 争取生态位 | — |

**注意：P5 从「默认」降为「可选」。** 安装器是最大的成本项和最低的战略价值项。

---

## 7. Go/No-Go 决策点

每个阶段末设明确的止损/转向条件：

| 检查点 | 继续条件 | 转向/放弃条件 |
|---|---|---|
| P0 后 | 报告被 ≥ 2 个安全媒体或 HN ≥ 50 分报道；precision ≥ 0.85 | 无人关注 → **退化为纯 CLI 工具**，不做品牌动作，专注做好 P1 |
| P1 后 | 30 天内 100+ star；被 ≥ 1 个外部项目采用（嵌入/依赖） | 无外部采用 → 优先做 CI/规则 registry 而非新功能 |
| P2 后 | precision ≥ 0.8 且有用户要求「开启阻断」 | precision 不达标 → **永久保持「只报不阻断」**，把产品定位为「证据生成器」而非「守门人」。这仍是有价值的产品（SkillMD 的立场） |
| 全程 | 维护者投入 ≤ 每周 10 小时 | 超出 → 收缩到 P0+P1（扫描器 + 报告），停止产品扩张 |

---

## 8. 最终建议（一句话版）

> **先做一份让所有人无法忽视的数据报告，再做一个所有人都能离线使用的扫描器，
> 然后定义「怎么验证一个 Skill」的标准，并且让别人用你的标准。**
>
> 不要试图成为安装入口 —— 那里已经有 724 万周下载。
> 要成为**验证标准** —— 那里目前只有一家有 10 亿估值、必须联网、且没人做声明校验。

**可行性结论：✅ 值得做。方向需要调整：从「包管理器」收窄为「验证层 + 标准 + 数据」。**

---

## 附录：数据来源

- Skillful.sh 生态报告（2026-09-30，聚合 55 目录）
- arXiv 2608.10906《GitSkills》（2026-07 采集，3.8M 文件 / 282k 仓库）
- arXiv 2602.08004（40,285 skill 数据驱动分析，18.5× / 20 天增长）
- arXiv 2603.02176《AgentSkillOS》（200K 规模评测）
- arXiv 2605.11418（metadata-only registry 投毒，86% 成对胜率）
- arXiv 2606.03024《SkillGuard: A Permission Framework for Agent Skills》（91.0% F1、56.5% over-declared / 17.4% under-declared）
- arXiv 2605.10990《Skill Drift Is Contract Violation》（同名系统）
- USENIX Security 2026《Do Not Mention This to the User: Detecting and Understanding Malicious Agent Skills in the Wild》
- Cloud Security Alliance 研究简报（2026-05 Agent Context Poisoning；2026-06 Poisoned Skills / ClawHub）
- Koi Security（Oren Yomtov）ClawHub 审计 2026-02；Unit 42 2026-02~05 追踪
- Snyk Labs《Skill Inspector》与 2026-02 生态审计；ToxicSkills 命名
- Socket.dev（2026-02 扫描 skills.sh；Series C $60M / $1B，2026-03）
- Endor Labs AURI 产品页（agentic security platform，policy enforce at moment of action）
- Check Point Research（Claude Code CVE-2025-59536 / CVE-2026-21852；Cursor MCP 攻击链）
- Anthropic 事故披露（2026-07-30，agent 发布恶意 PyPI 包，15 台真实系统运行）
- StepSecurity、Oligo Security（TeamPCP 2026-03 战役分析）
- Semgrep about / 融资历史；Tracecat、SubImage Show HN 数据点
- 各项目官方仓库与文档：snyk/agent-scan、skillmds/skillmd、agent-contracts/skill-preflight、
  vercel-labs/skills、skills-lock/skil-lock、skillpkg/spm、NVIDIA/SkillSpector、crates.io `skill`