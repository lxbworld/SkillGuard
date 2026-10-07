# SkillGuard — Threat Model

本文件同时描述：(A) SkillGuard **作为安装前的守门人**所防御的威胁；
(B) 被扫描 Skill **反过来攻击 SkillGuard 自身**的威胁。

> 核心原则（需求 §22）：**Treat the scanned Skill as hostile input.**
> 我们不做运行时沙箱，因此所有攻击面必须在「读到字节」之前就收敛。

---

## 1. 资产（Assets）

| 资产 | 为什么重要 |
|---|---|
| A1 凭据 | `~/.ssh`、`.env`、`.aws/credentials`、CI token —— Skill 脚本以用户权限运行 |
| A2 用户文件系统 | 项目文件、home 目录、可写路径 |
| A3 Agent 指令完整性 | SKILL.md 会被注入到模型上下文，等同于「以用户身份下指令」 |
| A4 Agent 配置 | `.claude/settings.json` 等可被篡改以持久化后门 |
| A5 已安装 Skill 集合 | 被投毒一个即横向扩散 |
| A6 供应链记录 | provenance / lockfile 被篡改则一切校验失效 |
| A7 SkillGuard 自身完整性 | 被绕过则整套信任层失效 |

---

## 2. 信任边界（Trust Boundaries）

```
 TB0  开发者/CI 自身        —— 可信
      ───────────────────────────────────────────────
 TB1  SkillGuard 进程边界   —— 内核级隔离（进程/文件系统权限）
      ───────────────────────────────────────────────
 TB2  解析器边界            —— 解析 SKILL.md / YAML / JSON
      ───────────────────────────────────────────────
 TB3  规则引擎边界          —— 不可信文本 vs 已提取结构化 token
      ───────────────────────────────────────────────
 TB4  安装写入边界          —— 首次从「只读」跨到「写 agent 目录」
      ───────────────────────────────────────────────
 TB5  Git 边界              —— 第三方远程仓库（不受我们控制）
      ───────────────────────────────────────────────
 TB6  网络边界              —— MVP 完全不跨越（安装 Git 源除外）
```

**TB4 是唯一的状态转换点**：在它之前，Skill 只是一堆字节；之后它成为 Agent 的一部分。
所有阻断逻辑必须在 TB4 之前完成（不变式 I1）。

---

## 3. 对被扫描 Skill 的威胁（T1–T10）

### T1 提示注入（Prompt Injection）
**目标** A3。**入口** `SKILL.md` 正文、`references/*.md`、`assets/*.md`。
**手法**：`ignore previous instructions`、伪造 system message、`do not tell the user`、
base64 / Unicode 混淆的指令、隐藏 HTML 注释、诱导读取其他文件并外传。

**检测（确定性）**
- 注入短语表（大小写不敏感 + 归一化后匹配）：`PI_INJECTION_OVERRIDE` / `PI_SYSTEM_IMPERSATION` /
  `PI_CONCEALMENT` / `PI_EXFIL_INSTRUCTION`
- 影子文本（base64 解码候选）复检
- 描述-行为不一致：`PI_DESCRIPTION_MISMATCH`（frontmatter description 与正文能力不匹配）

**残余风险**：**无法保证覆盖**。自然语言注入的语义面远大于规则面。
**诚实结论**：detection ≠ prevention。SkillGuard 的定位是**强制人类阅读证据**
（输出具体行号与原文），而非自动判罪。任何「零漏报」的宣传都是错误的。
后续可选的语义层（需求 §3 的 Optional AI Layer）也不得成为唯一防线。

### T2 凭据窃取
**手法**：读 `~/.ssh/id_rsa`、`.env`、`~/.aws/credentials`、`.git-credentials`、
`process.env` 全量打印、`printenv`、读取 shell history。

**检测**：`SECRET_PATH_READ`（路径表 + 模糊匹配）、`SECRET_ENV_DUMP`（`env`/`printenv`/`os.environ` 整体）、
`SECRET_EXFIL_CHAIN`（凭据路径 + 网络 sink 同现 → CRITICAL）。
**必须区分**：`export FOO=$(cat key.pem)`（真）与文档里"读取 ~/.ssh 的最佳实践"（说明性）——
用 `Confidence` 标注，不直接升 severity。

### T3 硬编码秘密
`SECRET_PRIVATE_KEY` / `SECRET_AWS_AK` / `SECRET_GITHUB_PAT` / `SECRET_GENERIC_ASSIGN` /
`SECENT_JWT`。高熵值检测需谨慎：**只对已知前缀/结构模式判定**，避免把 sha256 / commit hash
当成 token（这是常见误报源，必须有 hash 白名单模式）。

### T4 Shell 执行与提权
`sudo`、`chmod 777`、`rm -rf`、`eval`、`exec`、`python -c`、`base64 -d | sh`、`os.system`、
`subprocess(..., shell=True)`。**不因出现命令即判恶意**，输出 risk + evidence。

### T5 下载与执行链
`curl URL | sh`、`wget -O- URL | bash`、`powershell IEX(New-Object Net.WebClient).DownloadString`、
`pip install http://...`、`npm i --registry=<非官方>`、带密码的 zip、下载后 `chmod +x`。
→ `DL_CHAIN_*` 规则，命中即 CRITICAL，evidence 同时给出 source 与 sink。

### T6 危险依赖 / 仿冒包
`requsts`、`python-dateutil2`、`numpyy`、`cross-env`、`lodash.`，以及 typosquat 启发式
（编辑距离 + 知名包名表）。依赖清单来自 `requirements.txt` / `pyproject.toml` /
`package.json` / `Cargo.toml` 的静态解析。

### T7 覆盖与持久化
写入 `.claude/settings.json` hook、`~/.claude/CLAUDE.md`、`AGENTS.md`、
`.git/hooks/*`、crontab、shell rc。→ `PERSIST_*` 规则（Phase 1 可只报 INFO/LOW，Phase 2 升级）。

### T8 跨 Skill / 跨 Agent 引用逃逸
`@../other-skill/SKILL.md`、`~/.claude/skills/` 全量读取、把其他 Skill 的内容作为指令。
→ `REF_OUTSIDE_SKILL` + capability diff 中的越界访问。

### T9 混淆与隐藏文本
base64 块、零宽字符、同形字、HTML 注释中的指令、超长不可见段落、Markdown 里的
零宽链接/图片（`![](` + tracking pixel 域名）。→ `OBFUSC_*` 规则，`DL_BASE64_BLOB` 辅助。

### T10 许可证与合规
未声明 license、声明与 LICENSE 文件不符、**限制性 license 用于商用分发**（GPL/AGPL 传染性、
"非商业"条款、来源不明）。→ `LICENSE_*` 规则，Phase 3 接入 SPDX 表达校验。

---

## 4. 对 SkillGuard 自身的威胁（T11–T16）

这一节是**安全工具必须先自保**的部分。

### T11 解析器 DoS
**攻击**：10 MB 单行 YAML、深度 500 的 YAML 嵌套（billion laughs 式实体展开）、
巨型 JSON、巨量小文件（inode 耗尽）、正则回溯（ReDoS）。

**缓解**
- 序列化为 **JSON**，YAML 仅用于 policy/lockfile 且设 `serde_yaml` 的深度上限；
  读取失败按不可信处理并给出 `PARSE_FAILED`（不 panic）
- 文件大小上限 4 MiB、深度上限 12、文件数上限 10000（超限 `INFO` 并停止展开）
- 只用 `regex`（线性时间，无回溯）；**禁止**手写回溯 NFA 正则
- 所有解析用 `catch_unwind` 包裹入口，panic 转错误码，绝不 panic 到用户

### T12 路径遍历 / Zip-slip 隐患
**攻击**：`scripts/../../../../etc/cron.d/x`、`references/~/....ssh/id_rsa`。

**缓解**：`path-clean` 归一化后必须仍在 skill 根目录内，否则记 finding 而**不读取**该文件；
读取一律经 `SkillGuard::resolve_safe_path(root, rel) -> Result<Path>` 单一入口。

### T13 Symlink 攻击
**攻击**：`scripts/link -> ~/.ssh`，或 symlink 环 `a -> b -> a`。

**缓解**：`follow_links(false)`；发现指向根目录外的 symlink → `FS_SYMLINK_OUTSIDE`（MEDIUM），
不跟随。Windows 上 junction 同样视为 symlink。

### T14 不可信文件的解析型攻击
- `SKILL.md` 里嵌入控制字符（ANSI escape / 零宽）→ **终端注入**：
  恶意 Skill 可通过文件名/description 里的 ANSI 序列操纵用户终端显示，伪造扫描结果。
  **缓解**：所有输出到终端的字符串先过 `strip_ansi + NFC 归一化 + 长度截断`。
- 极长单行导致终端换行错乱 → 单字段输出上限（如 200 字符 + `…`）。

### T15 锁文件投毒
**攻击**：篡改 `SKILLGUARD.lock` 中的 `commit`/`content_digest`/`policy_decision` 使恶意 skill 合规。

**缓解**
- 锁文件写入是工具独占的（`generated_by` 字段 + `verifier` 记录 CLI 版本）
- `verify` 时**重算** digest 并与锁文件比对，不信任任何已记录的字段
- 锁文件本身纳入 git，PR diff 即审计面；提供 `skillguard diff` 展示能力面变化
- 读取锁文件时对 `source` 做白名单 scheme 校验（拒绝 `file://`、UNC、任意 `local:` 逃逸）

### T16 时序与环境影响
- SkillGuard 写入 agent 目录前必须先完成全部校验（不变式 I1）；
  若中途失败，**不留半成品**：写入临时目录 + 原子 rename
- 拒绝安装到非预期目录（`agents.rs` 目录表为唯一真源，不从环境变量读取任意安装路径）

---

## 5. 威胁 → 规则 → 严重度映射

| 威胁 | 规则 ID | 默认 severity |
|---|---|---|
| T1 | `PI_INJECTION_OVERRIDE`, `PI_SYSTEM_IMPERSATION`, `PI_CONCEALMENT`, `PI_EXFIL_INSTRUCTION` | HIGH |
| T2 | `SECRET_PATH_READ`, `SECRET_ENV_DUMP`, `SECRET_EXFIL_CHAIN` | HIGH / CRITICAL |
| T3 | `SECRET_PRIVATE_KEY`, `SECRET_AWS_AK`, `SECRET_GITHUB_PAT`, `SECRET_GENERIC_ASSIGN` | CRITICAL / HIGH |
| T4 | `SHELL_EXEC`, `SHELL_PRIVILEGE_ESCALATION`, `SHELL_DESTRUCTIVE` | MEDIUM / HIGH |
| T5 | `DL_PIPE_TO_SHELL`, `DL_REMOTE_INSTALL`, `DL_UNTRUSTED_DOMAIN`, `DL_PASSWORD_ARCHIVE`, `DL_CHAIN_FETCH_EXECUTE` | CRITICAL |
| T6 | `DEP_TYPOSQUAT`, `DEP_CUSTOM_REGISTRY`, `DEP_UNPINNED_SCRIPT` | HIGH |
| T7 | `PERSIST_AGENT_CONFIG`, `PERSIST_SHELL_RC`, `PERSIST_HOOK`, `PERSIST_CRON` | MEDIUM |
| T8 | `REF_OUTSIDE_SKILL` | MEDIUM |
| T9 | `OBFUSC_BASE64_BLOB`, `OBFUSC_ZERO_WIDTH`, `OBFUSC_HOMOGLYPH`, `OBFUSC_TRACKING_PIXEL` | MEDIUM |
| T10 | `LICENSE_MISSING`, `LICENSE_MISMATCH`, `LICENSE_RESTRICTIVE` | LOW / MEDIUM |
| T11 | `PARSE_FAILED`, `RESOURCE_LIMIT_EXCEEDED` | INFO |
| T12/13 | `FS_PATH_ESCAPE`, `FS_SYMLINK_OUTSIDE` | HIGH / MEDIUM |
| T15 | `LOCK_DIGEST_MISMATCH`, `LOCK_HAND_EDITED` | HIGH / MEDIUM |
| — | `MISMATCH_UNDECLARED_CAPABILITY`（diff 产生，非文本规则） | HIGH |
| — | `POLICY_VIOLATION`（policy 产生） | 按违规能力 |

---

## 6. 明确不在威胁模型内（Out of Scope）

诚实声明，避免给出虚假安全感：

1. **运行时行为**。我们不执行也不沙箱化 Skill。安装后的恶意行为不在防御范围。
2. **模型层漏洞**。SkillGuard 无法阻止模型自身被 jailbreak，也无法防止它执行危险指令。
   → 这是 arXiv SkillGuard（运行时权限框架）与 AgentBound 的领域，不是我们的。
3. **语义级 prompt injection**。启发式有高漏报率。我们输出证据让人判断，不宣称完备。
4. **零日与供应链上游投毒**。若 npm 上游包本身被投毒且其 tarball 合法，
   静态分析只能给出弱信号。
5. **多用户/企业 MDM 管控**。需求 §6 明确不做。
6. **MCP server 生态**。需求 §6 明确不做。
7. **Side-channel / 时序攻击**。非威胁模型。

---

## 7. 安全不变量（必须写成断言测试）

| ID | 不变量 |
|---|---|
| S1 | 扫描器从不 `exec` 被扫描文件，从不发起网络请求，从不读取环境变量中的凭据 |
| S2 | `policy_decision == Deny` 时，agent 目录与 skill 目录的文件系统快照完全不变 |
| S3 | 所有 Finding 必含 `file` + `line` + 原文 `evidence`（无证据不报 finding） |
| S4 | 同一输入的 `content_digest` 跨机器、跨 OS 一致 |
| S5 | 任何被写入终端的字符串都经过 ANSI 清理与长度限制 |
| S6 | 任何读取磁盘的路径都经过 `resolve_safe_path` |
| S7 | 扫描器对任意输入（含随机字节）不 panic |
| S8 | lockfile 中的 `declared_permissions` 与 `observed_capabilities` 在类型层面不可互相赋值 |