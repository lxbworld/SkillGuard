# Phase 0 — Large-Scale Corpus Security Study

**目的**：在写产品之前，先用一份无法被反驳的数据把项目立住。
**状态**：待批准。**技术前提**：只需 Phase 1 的扫描器 + 一个语料驱动模式。

---

## 0. 为什么这一步排在产品之前

在这个领域，「首个大规模实证」是唯一能拿到 HN 首页和安全媒体曝光的资产：

| 项目 | 知名度来源 | 曝光量级 |
|---|---|---|
| Snyk | 审计 3,984 个 skill（2026-02） | 独立报告 + Snyk Labs 官网实验页 |
| Socket.dev | 扫描 skills.sh 60,000+ skill | 博客 + 独立主页 + 6 分钟内发现 Mastra 攻击 |
| arXiv GitSkills (2608.10906) | 3,797,117 文件 / 282,200 仓库数据集 | 学术引用 |

同时它解决另外三件事：

1. **规则的真实精度** —— 用 100k 真实语料测 precision/recall，而不是自造 fixture
2. **数据集归属** —— 语料索引本身成为可被引用的公开资产（GitSkills 已被 alphaXiv 收录）
3. **分母** —— 「17.4% 的 skill 少声明权限」这类数字需要一个我们自己掌握的分母

---

## 1. 研究问题（可证伪的假设）

**主问题 R1**：Agent Skill 生态中，存在规模化的、系统性的权限声明缺失与危险行为模式。

**子问题**：

| ID | 问题 | 对应指标 |
|---|---|---|
| R1.1 | 有多少 skill 包含硬编码凭据？ | `SECRET_*` 命中率 |
| R1.2 | 有多少 skill 存在 `download → execute` 链？ | `DL_CHAIN_FETCH_EXECUTE` |
| R1.3 | 有多少 skill 执行 shell / 提权 / 破坏性命令？ | `SHELL_*` |
| R1.4 | 有多少 skill 访问敏感路径或环境变量？ | `SECRET_PATH_READ` / `SECRET_ENV_DUMP` |
| R1.5 | 有多少 skill 含确定性可检的提示注入？ | `PI_*` |
| R1.6 | **多少 skill 声明了 permissions？其中多少 under-declared？** | ⭐ 核心差异化指标 |
| R1.7 | 哪些混淆手法在野外实际被使用？ | `OBFUSC_*` 分布 |
| R1.8 | 声明与实际行为的差异率是多少？ | declared vs observed |
| R1.9 | 依赖声明是否完整/固定版本？ | `DEP_*` |
| R1.10 | 许可证声明与实际 LICENSE 文件是否一致？ | `LICENSE_*` |

**明确的非目标（防止研究跑偏）**：
- ❌ 不判断某个 skill 「是否恶意」（我们只报证据）
- ❌ 不做语义/意图判定
- ❌ 不评测模型能力
- ❌ 不研究 MCP server

---

## 2. 语料来源与抽样

### 2.1 数据源分层

| 层 | 来源 | 获取方式 | 抽样方式 |
|---|---|---|---|
| L1 公开 registry | skills.sh 排行榜 / skillmd.com API | 官方公开 API，遵守速率限制 | 按 install 计数分层 |
| L2 争议 registry | ClawHub | 公开索引 | **全量**（已知含恶意，含金量高） |
| L3 GitHub | `filename:SKILL.md` code search | GitHub REST API，认证 | 随机抽样 + 分层 |
| L4 学术数据集 | GitSkills (arXiv 2608.10906) | 作者申请 / 公开下载 | 复用其仓库元数据 |
| L5 生态目录 | skillsmp、skillful.sh、awesome 列表 | 公开 | 去重后随机 |

**目标总量**：N = 100,000 个唯一 skill（按内容 digest 去重）

### 2.2 分层抽样（Stratified Sampling）

必须分层，否则结论会被「AI Tool」类目主导（占 69.7%）。分层维度：

| 维度 | 分层 |
|---|---|
| 来源 | L1 / L2 / L3 / L4 / L5 |
| 规模 | <8 KB · 8–32 KB · 32–128 KB · >128 KB |
| 是否含脚本 | 无 `scripts/` · 有 shell · 有 python · 有 js/ts · 有其他 |
| 声明权限 | 有 permissions · 无 |
| 许可证 | 有 LICENSE · 无 · 声明与文件冲突 |
| 安装量（仅 L1） | Top 1% · 1–10% · 10–50% · 50–100% · 尾部 |

**每层抽样比例**必须在报告中公开，且**公布每层的 N**。
超容量层（如 L3 的 GitHub 全量）用**系统抽样**（按仓库 ID 哈希取模）而非简单随机，
以保证可复现且无偏。

### 2.3 可复现性（不可妥协）

每个被分析的 skill 记录三元组：

```json
{
  "source_id": "skills.sh/vercel-labs/skills@frontend-design",
  "commit": "<40-hex full sha>",
  "content_digest": "sha256:<64 hex>",
  "layer": "L1",
  "stratum": "scripts_shell|declared_none|size_8k_32k|tail",
  "scan_rule_version": "1.0.0"
}
```

**要求**：
- 拒绝 tag / branch / 短 SHA（架构 §7 的原则在语料采集上同样适用）
- 提交 `corpus-manifest.json` 到仓库的 `research/` 目录，可 diff、可复查
- 提供 `skillguard corpus reproduce <manifest>` 复现整个分析
- 记录采集时间窗（UTC），因为上游仓库会变动

> **这是本阶段最容易被忽略、但最决定公信力的细节。**
> 没有 pinned commit 的语料研究在安全领域是无效的。

---

## 3. 合规与伦理（必须先于技术）

这是本阶段最大的非技术风险。**必须在写第一行扫描代码前完成。**

### 3.1 硬性规则

| 规则 | 说明 |
|---|---|
| **R-1 只读，不执行** | 永远不运行、不安装、不 `npm install`/`pip install` 被测 skill。归档也只是存储字节 |
| **R-2 不再分发恶意内容** | 报告中**只发布**：规则 ID、内容 digest、行号、**脱敏后的**证据片段（域名保留、私钥/凭据截断）。**不发布**可直接运行的 payload |
| **R-3 速率限制** | 严格遵守 GitHub API 限制（认证 5,000 req/h）。自建节流器，默认 1 req/s，含指数退避与 429 熔断 |
| **R-4 尊重 robots.txt 与 ToS** | 各 registry 的 ToS 逐条审阅并记录（放 `research/TERMS-REVIEW.md`）。若某源禁止采集则排除，并在报告中说明该源的排除理由 |
| **R-5 不做个人画像** | 不分析作者身份、姓名、国籍、组织。仓库归属仅用于生态统计，不指向个人 |
| **R-6 数据最小化** | 语料索引不含任何个人联系方式；commit 作者字段在公开数据集里一律丢弃 |
| **R-7 协调披露** | 发现恶意样本后**先私下通知**对应 registry（ClawHub / skills.sh），给 7 天响应期，再公开。**这一条是信誉的生死线** |
| **R-8 蜜罐风险** | 不把扫描器接入任何会自动执行的自动化；GitHub Action 只读、只写 SARIF |

### 3.2 协调披露流程（R-7 细则）

```
发现恶意样本
  ├─ ① 生成内部工单，记录 digest + 规则 ID（不记录 payload 内容）
  ├─ ② 通知 registry 维护者（skills.sh / ClawHub），附 digest 与规则
  ├─ ③ 等待 7 天响应期
  ├─ ④ 若对方未处置 → 报告中以 digest 引用，仍不公开 payload
  └─ ⑤ 若对方处置 → 在报告中记为「已协调移除」，这本身就是正面故事
```

**额外收益**：这一步极可能带来与 registry 的合作（提供扫描能力），
是比曝光更有价值的长期资产。

### 3.3 工具自身的合规

- 优先使用 GitHub REST API + tarball 端点，**不做全仓库 git clone**（降低带宽与存储）
- 本地缓存加密、限容，采集结束后按策略清除原始 payload，仅保留 digest
- 扫描器在受限容器/低权限用户下运行（双保险，即使设计上不执行，也限制万一）

---

## 4. 指标定义（精确定义，避免歧义）

每个指标必须写清：分子、分母、分母包含什么、不包含什么。

### 4.1 主指标

```text
Prevalence(R) = |{ skill ∈ corpus : skill 有 ≥1 条匹配规则 R 的 finding }| / |corpus|
```

**分母**：`corpus` = 通过去重与有效性检查后的全部 skill。
**排除**：解析失败且无法提取 frontmatter 的 skill 需单独报告（不得静默丢弃，见 §6.3）。

### 4.2 必报的分层维度

每个 `Prevalence(R)` 必须同时按以下维度分层报告，否则无法解释：
来源层 · 规模桶 · 是否含脚本 · 安装量分位（仅 L1）· 许可证状态

### 4.3 精度/召回测量（核心可信度）

**抽样**：从每个分层随机抽 **500 个 skill**（分层合计 ≈ 2,000）组成标注集 `GOLD`。

**标注流程**：
1. 两名标注者独立标注（单人项目 → 至少 1 名外部志愿者 + 1 名复核）
2. 记录**一致性**：Cohen's κ，目标 ≥ 0.75；低于则先修规则定义再重新标
3. 分歧由第三方裁决，裁决记录进数据集
4. **标注者不得看到规则的输出细节**（避免锚定偏差）→ 提供一个 `skillguard inspect --no-rules` 模式，只给归一化文本与行号

**指标**：
```text
Precision(R) = TP / (TP + FP)      # 规则报了但人判误报
Recall(R)    = TP / (TP + FN)      # 人判有问题但规则没报
```
- 报告 **per-rule** 的 P/R，不用微平均掩盖坏规则
- 对低 precision 规则给出**具体误报样本**分析
- **不做任何事后调参**（不允许「看了标注集再改规则再报一次」）。若必须迭代，则标注集版本化
  （`GOLD-v1`、`GOLD-v2`），每个版本独立报告全部指标。这是学术诚信底线

### 4.4 横向对比基准（强烈建议做，成本低收益高）

在 `GOLD` 的 1,000 个子样本上，同时运行**至少 2 个现有工具**：

| 对比对象 | 命令 | 目的 |
|---|---|---|
| SkillMD | `npx skillmds scan <path>` | 生态最大 registry 的引擎 |
| skill-preflight | `npx skill-preflight scan <path>` | 评分路线的代表 |
| （可选）SkillSpector | Python | NVIDIA 出品，静态检查路线 |

**产出**：一张 `规则检出率 × 误报率 × 耗时 × 是否离线` 的对比表。

> 这一张表就是项目的技术护城河证明。
> 特别注意验证「离线」这一列 —— 这是所有现有商业方案的共同短板。

**注意**：运行竞品工具必须用其最新稳定版本、遵守其 ToS、只跑公开语料，
并在报告中说明版本号与运行方式（它们的输出会变，结果不可复现，需注明）。

---

## 5. 交付物

| # | 产物 | 路径 | 说明 |
|---|---|---|---|
| D1 | 研究协议预注册 | `research/PROTOCOL.md` | 假设、抽样、指标定义、**时间戳**。扫描前提交，防止事后改口径 |
| D2 | ToS 审阅记录 | `research/TERMS-REVIEW.md` | 每个数据源的 ToS 结论与合规依据 |
| D3 | 语料清单 | `research/corpus-manifest.json` | pinned commit + digest + 分层标签 |
| D4 | 标注集 | `research/gold/` | `GOLD-v1` + 标注指南 + 一致性统计 |
| D5 | 扫描原始结果 | `research/raw-findings.jsonl` | 每条 finding 一行（含 digest/rule/file/line） |
| D6 | 聚合数据集 | `datasets/skill-corpus-2026q4.jsonl(.zst)` | **可公开发布**，脱敏证据 |
| D7 | **主报告** | `docs/CORPUS_REPORT.md` | 结论、表格、分层分析、误报分析、局限 |
| D8 | 横向对比 | `docs/BENCHMARK.md` | 与 SkillMD / skill-preflight 的对比表 |
| D9 | arXiv 预印本 | — | 生态安全态势测量（第二作者可为外部研究者，提升可信度） |
| D10 | 技术博客 | — | 面向开发者的可读版本（HN 素材） |
| D11 | 协调披露记录 | `research/DISCLOSURE.md` | 时间线、通知对象、处置结果 |

### 5.1 主报告必须包含的诚实声明（写死在模板里，不许删）

```text
1. Detection is not judgement. 本研究不判定任何 skill 为恶意，只报告可复现的规则命中。
2. 规则有漏报。语义级提示注入的漏报率未知且必然非零。
3. 误报存在。所有 prevalence 数字都受 §4.3 的 precision 约束，
   真实 prevalence 的区间是 [P×点估计, 点估计]。
4. 语料有偏。GitHub code search 受平台索引限制，registry 有自身偏好，
   结论不必然外推到私有/企业内部 skills。
5. 语料会漂移。所有结论绑定采集时间窗与 commit，不能被永久引用。
```

---

## 6. 技术实现（最小新增）

只需在 Phase 1 扫描器之上加一个「批量驱动」，不新建子系统。

### 6.1 新增能力

```text
skillguard corpus fetch  --source <l1..l5> --limit N --out research/raw/
skillguard corpus scan   --manifest research/corpus-manifest.json --out research/raw-findings.jsonl
skillguard corpus stats  --findings <jsonl> --by layer,stratum --format markdown,json
skillguard corpus report --findings <jsonl> --gold research/gold/GOLD-v1 --out docs/
```

**核心诉求**：
- **吞吐**：100k skill 中位数扫描耗时需 < 15 ms（含 I/O）→ 约 25 分钟单机完成。用 rayon 并行 + 内容去重缓存
- **幂等**：同一 manifest 重跑产生**逐字节相同**的 jsonl（时间戳除外）
- **无网络**：`corpus scan` / `stats` / `report` 全程离线，只读本地 manifest
- **降级**：单条 skill 解析失败或超时必须记录并继续，不得中断整个批次（这是批处理工具最常见的脆弱点）

### 6.2 度量缓存

同一 digest 的扫描结果全局缓存（SQLite 或 `content_digest → findings` 映射），
重复扫描（重跑、横向对比）零成本。这是让 §4.4 的横向对比可行的前提。

### 6.3 失败必须可见

```text
total      = 100,000
scanned    =  99,847
failed     =    153     ← 必须单列一小节说明失败原因分布
skipped    =      0
binary     =     12
oversize   =     41
```
**禁止**把 failed 静默计入分母或丢弃。这是批量研究最容易被攻击的点。

---

## 7. 时间与成本估算

| 步骤 | 工期 | 成本 |
|---|---|---|
| 协议 + ToS 审阅 + 协调披露流程 | 3–5 天 | 0 |
| Phase 1 扫描器（前置依赖） | 2–3 周 | 0 |
| 语料采集（限速下） | 2–4 天 | 0（GitHub 免费层足够） |
| 标注集构建（含 κ 统计） | 2 周 | 0–少量（志愿者 / 找 1 名外部标注者） |
| 横向对比 | 3 天 | 0 |
| 主报告 + 博客 + 预印本 | 1 周 | 0 |
| **合计（不含 Phase 1）** | **约 6 周** | **≈ 0** |

**存储估算**：100k skill × 中位数 15 KB ≈ 1.5 GB 原始内容，
去重后约 0.8 GB，压缩后 ~300 MB。个人机器完全可承受。

**唯一的真实成本是注意力**：约 6 周 × 每周 10 小时 ≈ 60 小时。
这是判断是否继续的**唯一硬门槛**（对照 MVP.md §7 的维护者投入上限）。

---

## 8. 执行顺序（每个 gate 都可停）

```
G0  协议 + ToS 审阅通过？              ──► 否 → 重新选数据源，或放弃某些源
G1  扫描器 Phase 1 全绿 + 吞吐达标？    ──► 否 → 回到 Phase 1，不做研究
G2  坐标披露流程已建立（含 registry 联系方式）？── 否 → 先解决再采集
G3  GOLD-v1 κ ≥ 0.75？                 ──► 否 → 修规则定义，重标
G4  Precision ≥ 0.85 且 Recall ≥ 0.6？ ──► 否 → 迭代 GOLD-v2，双版本报告
G5  已协调通知 registry？                ── 否 → 不公开发布报告
G6  报告已发布且数据集已公开？          ──► 进入 Phase 1 产品化
```

**G4 是关键**：如果精度不达标，**不要**通过放宽口径来凑，而是**如实报告低精度**
并把结论限定为「上界估计」。一个诚实的「我们精度只有 0.62」比一个注水的 0.95 有价值得多。

---

## 9. 已知局限（预注册，避免事后找借口）

1. GitHub code search 只索引满足平台条件的文件 → 语料是下界
2. 公开 registry 的 skill 已被部分审核过，与「长尾私有 skill」分布不同
3. ClawHub 已知被投毒，其 prevalence **不能**外推到其他 registry（必须分开报告）
4. 静态分析对语义级注入无能为力（漏报未知）
5. 单时间窗快照，不反映时间演化
6. 标注者是我们自己/熟人，存在立场偏差 → 用 κ 与外部标注者缓解，但不能完全消除

---

## 10. 与后续阶段的衔接

```
Phase 0 产出 ─┬─→ 分层 prevalence + 误报分析 ──→ 反哺规则设计与 severity 校准
              ├─→ GOLD-v1 标注集 ──────────────→ 变成项目的永久回归基准
              ├─→ 公开数据集 ─────────────────→ 学术引用的长期 backlink
              ├─→ 横向对比表 ─────────────────→ README 的技术护城河
              └─→ 与 registry 建立联系 ─────────→ 长期合作入口

Phase 1 输入：GOLD-v1 已是现成的真实回归测试集（比自造 fixture 强得多）
```

> **一个被低估的收益**：`GOLD-v1` 会成为项目最有价值的资产之一。
> Semgrep 的 3000+ 社区规则正是这样滚起来的 ——
> 我们没有社区规模，但可以先有 2,000 个**真实、人工标注、公开**的标注样本。