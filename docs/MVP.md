# SkillGuard — MVP 范围与路线

技术栈：Rust（单二进制，离线，零 LLM）。本文件定义交付边界与验收标准。

---

## 1. 命名决策（待定，先用 `skillguard`）

调研发现 **arXiv 2606.03024 "SkillGuard: A Permission Framework for Agent Skills"**
以及 **2605.10990 "Skill Drift Is Contract Violation"** 中的同名系统。

| 方案 | 优点 | 缺点 |
|---|---|---|
| **A. 保留 `skillguard`**（当前） | GitHub 地址已建、仓库名已定 | 与论文同名，需在 README 主动声明关系 |
| B. 改名 `skilltrust` / `sgt` | 无冲突 | 需重建仓库，且 `SkillGuard` 一词更贴切 |

**建议：保留 A**，README 首段明确「本项目 ≠ arXiv 2606.03024 论文的官方实现，
我们实现其 permission manifest 思想的 pre-install、纯静态版本」。
这是信誉加分而非减分。**命名在 Phase 2 开始前最终确认。**

CLI 二进制名：`skillguard`。

---

## 2. 范围决策：与调研结论对齐

原需求 §20 的 Phase 划分基本合理，但调研后做两处调整：

**调整 1：Phase 3（provenance/lockfile）提前与 Phase 2 合并的诱因**
`skil-lock` 已经占了 capability lockfile。我们的 lockfile 必须**一开始就设计成含
`declared_permissions` + `mismatches`**，否则后期无法重构。因此 lockfile 的**schema**
在 Phase 2 定义，**provenance 采集**（git 元数据）可留在 Phase 3。

**调整 2：Phase 1 加入 declared 字段的读取**
frontmatter 里的 `permissions`（或 `skillguard.permissions`）从 Phase 1 就解析并保留，
只是 Phase 1 不做 diff。这样 fixtures 可以从第一天起就带声明。

---

## 3. Phase 1 — Scanner（第一个可交付）

### 交付物
`skillguard scan <path>...` + `inspect` + `rules`
- SKILL.md frontmatter 解析（含 `permissions` 声明字段）
- 目录安全遍历
- 归一化管线（NFKC / 零宽 / base64 影子文本 / 同形字标记）
- 规则集：secrets / shell / network / filesystem / download(链) / injection(启发式) / obfuscation
- 输出：text / json / sarif
- 退出码：`--fail-on <SEVERITY>` 控制
- 风险等级：INFO / LOW / MEDIUM / HIGH / CRITICAL
- 每个 finding 必须有 `file` + `line` + `evidence`（不变量 S3）

### 规则 ID 清单（Phase 1 必须全部实现）
```
SECRET_PRIVATE_KEY, SECRET_AWS_AK, SECRET_GITHUB_PAT, SECRET_GENERIC_ASSIGN,
SECRET_JWT, SECRET_PATH_READ, SECRET_ENV_DUMP, SECRET_EXFIL_CHAIN,
SHELL_EXEC, SHELL_PRIVILEGE_ESCALATION, SHELL_DESTRUCTIVE, SHELL_EVAL,
NET_HTTP_CLIENT, NET_FETCH_CALL, NET_DOMAIN_LITERAL, NET_DYNAMIC_URL,
FS_SENSITIVE_PATH, FS_ABSOLUTE_PATH, FS_HOME_ACCESS, FS_RECURSIVE_WALK,
FS_PATH_ESCAPE, FS_SYMLINK_OUTSIDE,
DL_PIPE_TO_SHELL, DL_REMOTE_INSTALL, DL_UNTRUSTED_DOMAIN,
DL_PASSWORD_ARCHIVE, DL_CHAIN_FETCH_EXECUTE, DL_BASE64_BLOB,
PI_INJECTION_OVERRIDE, PI_SYSTEM_IMPERSATION, PI_CONCEALMENT,
PI_EXFIL_INSTRUCTION, PI_DESCRIPTION_MISMATCH,
OBFUSC_ZERO_WIDTH, OBFUSC_HOMOGLYPH, OBFUSC_TRACKING_PIXEL,
PERSIST_AGENT_CONFIG, PERSIST_SHELL_RC, PERSIST_HOOK,
DEP_TYPOSQUAT, DEP_CUSTOM_REGISTRY, DEP_UNPINNED_SCRIPT,
LICENSE_MISSING, LICENSE_MISMATCH
```

### 验收标准
1. `tests/fixtures/malicious/` 下**每一个** fixture 至少命中一条预期规则；
   测试中显式列出 `expected_rules`，断言**命中集合包含**它（不要求完全相等）。
2. `tests/fixtures/safe/` 下**零 finding**（severity ≥ LOW）。
3. `tests/fixtures/obfuscated/` 下命中与 `malicious/` 同款内容一致的规则集。
4. `tests/fixtures/edge_cases/`（空文件、10 MB 单行、symlink 环、二进制、NUL 字节、
   巨量小文件）**不 panic**，退出码 ∈ {0, 1}。
5. 扫描全程无网络访问（测试环境禁用网络可跑通）。
6. `scan --format sarif` 通过 `sarif-validator` schema 校验。
7. 单个 200 KB SKILL.md 扫描耗时 < 100 ms（release 构建，4 核）。

---

## 4. Phase 2 — Capability / Permissions / Policy（差异化核心）

### 交付物
`skillguard inspect` / `diff` / `policy check` / `approve`
- `CapabilitySet`（observed）推导
- `PermissionDecl`（declared）解析 + 归一化
- **`declared_vs_observed()` 差分**：三类结果
  - `over_declared`：声明了但未观察到（不阻断，提示冗余）
  - `under_declared`：观察到但未声明（**阻断**，HIGH）
  - `conflicting`：声明互相矛盾（阻断）
- Policy 引擎（`SKILLGUARD.policy.yaml`）+ 四态决策
- 规则级 `ignore` 与全局 `exclude`

### 差分的确定性与误报
关键设计：**只对「不可从文档解释」的观察值算 under_declared**。
- shell 命令：`git` / `ls` 出现在示例里通常不是能力声明问题 → 只在脚本文件中观测并计入
- URL：文档中的链接属于「说明性引用」，只有脚本/代码中的 URL 计入 observed network
- 文件路径：同理，只有代码中的路径计入

这条规则让 under_declared 的 precision 达到可用水平。**Phase 2 第一周就要建
precision 测试集**（至少 30 个真实 skill 手工标注），达不到 0.8 则回退到「只报不阻断」。

### 验收标准
1. `diff` 对 30 个真实 skill 的 under_declared precision ≥ 0.8，recall ≥ 0.5。
2. `policy check` 在 `network.allow: false` 时对任意含出网能力的 skill 返回 `Deny`。
3. `deny` 时文件系统快照零变化（不变量 S2，有断言测试）。
4. 策略文件含非法字段/类型时输出明确错误而非静默忽略。

---

## 5. Phase 3 — Hash / Provenance / Verify

### 交付物
`skillguard hash` / `verify` / `lock` / `import`
- `sgdir-v1` 目录摘要（架构 §6）
- git provenance 采集（拒绝短 SHA / tag / branch）
- SPDX license 识别与表达式校验
- `SKILLGUARD.lock` v1 schema
- `import skills-lock.json`（互操作，见调研 §2.5）

### 验收标准
1. 同一目录两次计算 digest 一致；改 1 字节必变（跨 3 个平台 CI 验证）。
2. `verify` 能检出：commit 不匹配、digest 不匹配、lock 被手改。
3. `import skills-lock.json` 保留 `computedHash` 为 `legacy_digest`，且可 `verify` 通过。
4. tag / branch 形式的版本输入被拒绝并给出提示。

---

## 6. Phase 4 — add / install / update

### 交付物
- source spec：`github:owner/repo[/path]`、`git+https://`、`path:`（本地）
- `add` 编排：解析 → 扫描 → diff → policy → (阻断 | 审批) → 写锁 → 安装
- agent 目录注册表（架构 §2 `agents.rs`，唯一真源）
- `install` 严格按锁文件（内容不一致即失败，不静默重装）
- `update` 重新走全流程；digest 变化 → **旧审批自动失效**

### 验收标准
1. `add` 一个 CRITICAL skill 被阻断，且 agent 目录零写入。
2. `approve` 后再 `install` 成功，`SKILLGUARD.lock` 含审批人/时间/依据 digest。
3. 锁文件 digest 与磁盘不符时 `install` 失败退出码 2。
4. `update` 导致 digest 变化时，未重新审批则拒绝安装。

---

## 7. Phase 5 — CI / SARIF / Action

- `skillguard/action@v1`：读 SARIF 上传 Code Scanning
- `--fail-on`、`--format markdown` 输出 PR 评论
- 规则目录文档化（`skillguard rules --markdown`）
- 需要时可与 `skil-lock` 的 approvals 文件共存（我们输出建议片段，不强制）

---

## 8. 延后 / 不做

| 项 | 理由 |
|---|---|
| Registry / search / publish | 需求 §6 明确禁止；也是我们不与人竞争的地方 |
| LLM 语义分析 | 需求 §3 禁止作为核心。可作未来可选层 |
| Runtime sandbox / 强制执行 | 属 arXiv SkillGuard / AgentBound 领域 |
| tree-sitter 跨语句数据流 | Phase 1 用 window join；precision 不足时再引入 |
| 多语言依赖漏洞库对接 | Phase 1 只做仿冒/registry 检测，真实漏洞库走 OSV（Phase 5+） |
| 遥测 / 云端 | 需求 §4 local-first |

---

## 9. 风险登记

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| under_declared 误报率过高 | 中 | 阻断用户正常安装 | 只对代码文件计数；先「只报不阻断」积累数据再开阻断 |
| skil-lock 抢先做 declared-vs-observed | 中 | 差异化削弱 | 先发 `SKILLGUARD.lock` spec（CC BY），像 skil-lock 一样占规范位 |
| 与 arXiv SkillGuard 撞名致误解 | 已发生 | 中 | README 首段声明互补关系 + 引用 |
| 规则集被绕过（对抗混淆） | 高 | 中 | 归一化管线 + 对抗 fixture 持续补充；坦诚「不能完备」 |
| 单人/单模型开发速度 | 中 | 中 | 每条规则独立可加；fixtures 驱动开发 |
| Rust 正则/解析的边界 bug | 中 | 高 | clippy `-D warnings`、`cargo deny`、不变量断言测试 |

---

## 10. 里程碑

| 阶段 | 内容 | 出口条件 |
|---|---|---|
| M1 | Phase 1 全部 | §3 的 7 条验收标准全过 |
| M2 | Phase 2 全部 | §4 的 4 条验收标准全过 |
| M3 | Phase 3 全部 | §5 的 4 条验收标准全过 |
| M4 | Phase 4 全部 | §6 的 4 条验收标准全过 |
| M5 | Phase 5 全部 | Action 可在示例仓库跑出 Code Scanning 结果 |

**MVP 成功判定**（对应需求 §23）：`skillguard add <suspicious-skill>` 能在安装前
稳定报出全部 7 类风险（凭据访问 / shell 执行 / 文件系统 / 网络 / 可疑下载 / 提示注入 / 危险依赖），
`policy check` 能阻断违规 skill，`verify` 能确认 source+commit+hash 三元绑定，
`install` 能基于锁文件完成可复现安装。