# SkillGuard — Architecture

技术栈：**Rust（edition 2021，MSRV 1.78）**，单二进制，零运行时依赖。
本文件描述架构与接口边界，不含实现代码。

---

## 1. 技术选型理由（对比需求文档 §18 的 Python 建议）

需求文档原本建议 Python（Typers/Pydantic/PyYAML/Rich）。改为 Rust 的理由：

| 维度 | 说明 |
|---|---|
| **单二进制分发** | CI / pre-commit hook / GitHub Action 里无需 Node 或 Python 运行时。安全工具必须能在任何机器上跑起来，否则会被绕过。 |
| **零依赖供应链** | 本项目本身是供应链安全工具。若自身依赖树巨大（tree-sitter grammars + LLM SDK），讽刺且危险。Rust 依赖少且可审计。 |
| **确定性可重复** | 无 GC、无动态加载、无时间/随机隐式依赖。lockfile 哈希可稳定。 |
| **长驻 installer 性能** | 递归扫描 + SHA256 大目录，`sha2` + rayon 足够快（MVP 用单线程 + `walkdir`）。 |
| **DeepSeek 可维护性** | 需求约束是「单一模型能完成开发」。Rust 的编译期类型检查 + clippy 让 AI 生成的代码错误更早暴露。 |

代价：tree-sitter 的 Rust 绑定成熟度不如 Python；MFA/交互式 TUI 成本更高。
**应对**：MVP 不依赖 tree-sitter（见 §5）。

---

## 2. Crate 结构

单 crate + 清晰模块边界（lib + bin 双入口）。不做过早 workspace 拆分。

```
skillguard/
├─ Cargo.toml
├─ LICENSE                      # Apache-2.0
├─ NOTICE
├─ README.md
├─ src/
│  ├─ lib.rs                    # 稳定公共 API（供嵌入其他 Rust 工具）
│  ├─ main.rs                   # CLI 入口（clap）
│  ├─ models/                   # 纯数据类型，零依赖，serde
│  │  ├─ mod.rs
│  │  ├─ skill.rs               # SkillManifest, SkillDocument, Frontmatter
│  │  ├─ capability.rs          # Capability, CapabilitySet, PermissionDecl
│  │  ├─ finding.rs             # Finding, Severity, Confidence, Evidence
│  │  ├─ policy.rs              # Policy, PolicyDecision, Violation
│  │  ├─ provenance.rs          # Provenance, SourceRef
│  │  ├─ lockfile.rs            # SkillGuardLock
│  │  └─ report.rs              # ScanReport / ScanSummary
│  │
│  ├─ parser/                   # SKILL.md → SkillDocument
│  │  ├─ mod.rs                 # frontmatter 切分（byte-level，不依赖 YAML 行首假设）
│  │  ├─ frontmatter.rs         # serde_yaml 子集，安全反序列化
│  │  ├─ markdown.rs            # 提取 code fence / 行号映射
│  │  └─ references.rs          # 解析 references/ assets/ scripts/ 内引用
│  │
│  ├─ scan/                     # UNTRUSTED INPUT 的唯一入口
│  │  ├─ mod.rs                 # ScanEngine：编排所有 rule
│  │  ├─ rule.rs                # trait Rule + RuleContext + 契约
│  │  ├─ walk.rs                # 安全目录遍历（symlink / depth / size 限制）
│  │  ├─ text.rs                # 归一化：Unicode NFKC、隐藏字符、base64 候选提取
│  │  ├─ rules/
│  │  │  ├─ mod.rs
│  │  │  ├─ secrets.rs          # SECRET_* 规则集
│  │  │  ├─ shell.rs            # SHELL_* 规则集
│  │  │  ├─ network.rs          # NET_* 规则集
│  │  │  ├─ filesystem.rs       # FS_* 规则集
│  │  │  ├─ download.rs         # DL_* 规则集（含 download→execute chain）
│  │  │  └─ injection.rs        # PI_* 规则集（deterministic heuristics）
│  │  └─ dependency.rs          # package.json / requirements.txt / pyproject 解析
│  │
│  ├─ capability/               # observed capabilities 推导
│  │  ├─ mod.rs
│  │  ├─ derive.rs              # findings → CapabilitySet
│  │  └─ declared.rs            # 从 permissions 字段读 PermissionDecl
│  │
│  ├─ diff/                     # ⭐ 差异化核心
│  │  └─ mod.rs                 # declared_vs_observed() → Mismatch 列表
│  │
│  ├─ policy/
│  │  ├─ mod.rs
│  │  ├─ schema.rs              # SKILLGUARD.policy.yaml 解析
│  │  └─ engine.rs              # 策略求值，输出 PolicyDecision
│  │
│  ├─ hash/                     # 内容寻址
│  │  └─ mod.rs                 # merkle-ish 目录哈希（canonical serialization）
│  │
│  ├─ provenance/
│  │  ├─ mod.rs
│  │  └─ git.rs                 # git 元数据（subprocess，非 libgit2，MVP 取舍）
│  │
│  ├─ lockfile/
│  │  ├─ mod.rs
│  │  ├─ schema.rs              # SKILLGUARD.lock v1
│  │  └─ migrate.rs             # skills-lock.json → SKILLGUARD.lock（互操作）
│  │
│  ├─ install/
│  │  ├─ mod.rs                 # add/install/update 编排
│  │  ├─ source.rs              # source spec 解析（github:/path:/git/url）
│  │  ├─ agents.rs              # agent 目录注册表（.claude/.cursor/.agents/...）
│  │  └─ approve.rs             # 审批落库
│  │
│  └─ report/
│     ├─ mod.rs
│     ├─ text.rs                # 人类可读（表格 + 证据行）
│     ├─ json.rs
│     ├─ sarif.rs               # SARIF 2.1.0（GitHub Code Scanning）
│     └─ markdown.rs            # PR 评论
│
├─ tests/
│  ├─ fixtures/
│  │  ├─ safe/                  # 应当零 finding
│  │  ├─ malicious/             # 必须命中指定规则
│  │  ├─ suspicious/            # 必须给出 evidence 但不升 severity
│  │  ├─ obfuscated/            # base64 / Unicode 混淆
│  │  └─ edge_cases/            # 空文件、超大文件、symlink 环、二进制
│  ├─ parser_tests.rs
│  ├─ scan_rules_tests.rs       # 每条 rule 一个 regression test（需求 §21.10）
│  ├─ diff_tests.rs
│  ├─ policy_tests.rs
│  ├─ lockfile_tests.rs
│  └─ golden/                   # 输出快照
└─ docs/
```

**关键边界约束（架构级强制）**：
- `models/` 与 `hash/` **不得依赖任何其他内部模块**。它们是契约层。
- `scan/` **不得**依赖 `install/`。防止「扫描器为了安装而放宽判断」。
- `scan/` 内**禁止** `std::process::Command`（除 `provenance::git`）与 `std::net`。
  用 `#![forbid]` / clippy lint 在 CI 强制。

---

## 3. 依赖策略（极简）

| 用途 | crate | 备注 |
|---|---|---|
| CLI | `clap` (derive) | |
| 序列化 | `serde`, `serde_json` | |
| YAML | `serde_yaml`（已弃用警告则改 `serde_norway` 或 `saphyr`） | frontmatter / policy |
| TOML | `toml` | pyproject 解析 |
| 正则 | `regex` | 无回溯，线性时间，防 ReDoS |
| SHA256 | `sha2` | |
| 目录遍历 | `walkdir` | 带 `follow_links(false)` |
| glob | `globset` | |
| 路径规范化 | `path-clean`, `path-slash` | 处理 `..` / Windows 分隔符 |
| 颜色输出 | `owo-colors` / `anstream` | 自动禁用（非 TTY） |
| 错误 | `thiserror`, `anyhow`（仅 bin） | |

**禁止依赖**：任何 LLM SDK、任何 HTTP 客户端（Phase 4 安装 Git 源除外）、任何 telemetry crate。

CI 加 `cargo deny`：拒绝 `unsafe` 代码（`#![forbid(unsafe_code)]`）、拒绝多余来源。

---

## 4. 核心数据流

```
                        ┌──────────────────────┐
                        │  UNTRUSTED INPUT     │
                        │  SKILL.md scripts/   │
                        │  package.json URLs   │
                        └──────────┬───────────┘
                                   │  parser::parse  (byte-safe, 有限额)
                                   ▼
                        ┌──────────────────────┐
                        │   SkillDocument      │  只读数据
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
      ┌───────────────┐   ┌────────────────┐   ┌──────────────────┐
      │ ScanEngine    │   │ declared perms │   │ dependencies     │
      │ → Vec<Finding>│   │ (frontmatter)  │   │ (lockfile-free)  │
      └───────┬───────┘   └────────┬───────┘   └────────┬─────────┘
              │                     │                    │
              ▼                     │                    │
      ┌───────────────┐             │                    │
      │ CapabilitySet │◄────────────┴────────────────────┘
      │  (observed)   │        derive() + dependency 分析
      └───────┬───────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ diff::declared_vs_observed()          │  ⭐ 差异化核心
      └───────┬───────────────────────────────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ policy::evaluate(SkillDocument,       │
      │                  CapabilitySet,       │
      │                  Mismatch)            │
      └───────┬───────────────────────────────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ PolicyDecision                        │
      │  allow | warn | require_approval|deny │
      └───────┬───────────────────────────────┘
              │
      ┌───────┴────────┬─────────────┬──────────────┐
      ▼                ▼             ▼              ▼
  report::render  install::add   hash::dir_hash  provenance::collect
  (text/json/     (阻断在 deny)                  (source+commit+digest)
   sarif/md)            │
                         ▼
                 SKILLGUARD.lock  →  install::install(agent dirs)
```

**不变式（Invariant）**：
- I1：`deny` 的决策下，任何文件都不得被写入 agent 目录。
- I2：写入 `SKILLGUARD.lock` 的 `permissions` 字段必须来自 `declared`，`observed` 必须来自扫描；两者永不混用。
- I3：`content_digest` 的计算必须是 **canonical serialization**，同一内容在任何机器上结果一致。
  （规范见需求 §23「可复现安装」）

---

## 5. Scanner 设计

### 5.1 Rule 契约

```rust
pub trait Rule {
    fn id(&self) -> RuleId;                    // "SECRET_PRIVATE_KEY"
    fn default_severity(&self) -> Severity;
    fn applies_to(&self, kind: ArtifactKind) -> bool;   // Frontmatter / Markdown / Script / Manifest
    fn scan(&self, ctx: &RuleContext) -> Vec<Finding>;
}
```
`RuleContext` 提供：归一化文本 + **原始**文本 + 行偏移映射 + 已提取的 URL/domain/shell token 集合（跨规则共享，避免重复计算）。

### 5.2 为什么 MVP 不用 tree-sitter

正则 + YAML/JSON parser 已能覆盖需求 §8 全部确定性检查。
tree-sitter 在本项目的真实价值只有一处：**在 Python/JS/shell 中做跨语句的
download→execute 数据流分析**（`curl ... | sh` 这类组合）。

**决策**：MVP 用「同 line + 相邻 line」的 window join 实现 chain 检测；
若 precision 不足，Phase 1 末尾再对 `scripts/` 目录引入 `tree-sitter-bash` /
`tree-sitter-python`（feature-gated），且仅用于 `DL_CHAIN_*` 规则，不影响其他规则。

### 5.3 归一化管线（对抗混淆）

所有文本规则作用于**归一化视图**，但 evidence 保留原文片段：

1. Unicode NFKC 归一
2. 移除零宽字符（U+200B–200D, U+FEFF, U+00AD, 各类 variation selector）
3. 同形字（homoglyph）标记：非 ASCII 且形似 ASCII → 记录 `obfuscation_suspected`
4. Base64 候选：长度 ≥ 24 且字符集合法 → 生成**影子文本**供 injection 规则扫描，
   同时保留 `DL_BASE64_BLOB` finding
5. 行偏移双向映射，保证 evidence 的行号指向原始文件

### 5.4 下载→执行链检测

需求 §8 强调 `download → execute` 而非单点命中。实现为**三段式 token 序列匹配**：

```
segments = [ NET_FETCH(src) , ARCHIVE|archive , EXEC(shell) ]
chain rule 匹配同一条命令或相邻两行内的序列，severity 提升到 CRITICAL
```
输出必须同时包含 src / sink 两个位置（`evidence.secondary`）。

### 5.5 目录遍历的安全限制

对抗 symlink 环、遍历到 skill 之外、超大文件：

- `follow_links(false)`；遇到 symlink 只记录 `FS_SYMLINK_OUTSIDE`，不跟随
- 最大深度默认 12，最大单文件 4 MiB（超出 → `INFO`，不解析）
- 二进制文件（无 UTF-8）跳过并记录
- 显式排除 `.git/`、`node_modules/`、`target/`、`__pycache__/`

---

## 6. 哈希规范（可复现安装的基石）

**目录摘要算法 `sgdir-v1`：**

```
1. 遍历文件，按 POSIX 风格相对路径（'/' 分隔，Unicode NFC）字典序升序排序
2. 对每个文件：
     h_i = SHA256( b"sfg1\0" + relpath_bytes + b"\0" + mode_octal + b"\0" + content_bytes )
3. digest = SHA256( b"SKILLGUARD-DIR-v1\0" + concat(h_i) )
4. 输出 "sha256:" + hex(digest)
```

`mode_octal` 只纳入可执行位（`0o755` / `0o644`），避免跨平台 umask 差异导致不可复现。
**明确排除**：`.git/`、`*.lock`（防止自指）、`SKILLGUARD.lock` 自身。

这与 `skills-lock.json` 的 `computedHash` 不兼容 → `lockfile::migrate` 提供转换，
并在转换时**保留原 `computedHash`** 作为 `legacy_digest` 以便回溯校验。

---

## 7. Provenance 采集

```yaml
provenance:
  source: github:user/financial-analysis
  repository: https://github.com/user/financial-analysis
  commit: <40-hex full sha>          # 禁止短 SHA / 分支名 / tag
  tree_digest: "sha256:..."
  author: <git author, 仅提示>
  license: MIT                        # SPDX 表达式
  license_source: frontmatter | LICENSE file | unknown
  observed_at: 2026-10-07T12:00:00Z  # second 精度，避免 lockfile 抖动
```

- **拒绝短 SHA / tag / branch**（与 `skills-lock` 的教训一致：漂移即非确定性）。
- `provenance::git` 通过 `git` 子进程只读调用（`rev-parse`, `config`, `log -1`）。
  不引入 `git2`：libgit2 的 TLS/证书行为会引入网络与供应链面，而 MVP 只需读本地已有仓库。
  **若输入不是 git 仓库，`source`/`commit` 为 null，并明确标记 `provenance.incomplete: true`。**
- SPDX license：`spdx` crate 做表达式合法性校验；未知 license 归一为 `LicenseRef-*` 而非报错。

---

## 8. Policy 与决策

```yaml
policy_version: 1
policy:
  network:
    outbound:
      allow_domains: ["api.example.com"]
      deny_domains: ["*"]
  filesystem:
    allow_paths: ["./data/**"]
    deny_paths: [".ssh/**", ".env"]
  shell:
    deny: ["sudo", "rm -rf"]
  secrets:
    access: false
  findings:
    deny_severity: CRITICAL
    require_approval_severity: HIGH
```

`PolicyDecision` 四态：`Allow` / `Warn` / `RequireApproval` / `Deny`。
`Deny` 是唯一阻断安装的状态（不变式 I1）。

**审批**写入 `SKILLGUARD.lock` 的 `approvals[]`（reviewer + reason + timestamp + 决策依据摘要）。
与 `skil-lock` 的 PR 级作用域不同：MVP 用**持久审批**，
并记录审批所依据的 `content_digest` — 若内容变了，审批自动失效（这是它的缺陷，我们在设计阶段就避开）。

---

## 9. Lockfile 设计

```yaml
lockfile_version: 1
skills:
  financial-analysis:
    source: github:user/financial-analysis
    commit: <40-hex>
    content_digest: "sha256:..."
    legacy_digest: null
    version: 1.2.0
    license: MIT
    declared_permissions:      # 来源：frontmatter（不可被扫描结果污染）
      network: { outbound: ["api.example.com"] }
    observed_capabilities:     # 来源：扫描器
      network: { outbound: ["api.example.com", "evil.example.com"] }
    mismatches:                # ⭐ 差异快照，安装当时的状态
      - capability: network.outbound
        kind: under_declared
        detail: "evil.example.com"
        severity: HIGH
    dependencies:
      - { ecosystem: pypi, name: pandas, version_spec: ">=2.0" }
    policy_decision: allow
    approved_by: null
    observed_at: 2026-10-07T12:00:00Z
```

与 `skills-lock.json` 的关系：**不替代，只读取并迁移**（需求未禁止互操作，且这是最大生态入口）。
提供 `skillguard import skills-lock` 生成初版 `SKILLGUARD.lock`，把所有 hash 锁定行为纳入
本工具的 policy 门内。

---

## 10. CLI 表面

```
skillguard scan <path>...            # evidence 优先的报告 + 退出码
skillguard inspect <path>            # 只列 capabilities / dependencies，不判定
skillguard diff <path>               # declared vs observed
skillguard policy check <path>       # 策略求值
skillguard verify <path|--lock>      # source + commit + digest 三元校验
skillguard add <source>              # 解析 → 扫描 → policy → 阻断/审批 → 写锁 → 安装
skillguard install                   # 严格按锁文件安装
skillguard update [name]             # 重新解析，须过 policy 与重新审批
skillguard lock                      # 把当前状态写入锁文件
skillguard approve <name>            # 记录审批
skillguard import <lockfile>         # skills-lock.json / package.json+npm 迁移
skillguard rules                     # 规则目录（含 id / severity / 说明 / 关闭方式）
```

**退出码**：`0` 通过 · `1` 策略违规 · `2` 完整性失败 · `3` 用法错误 · `4` 内部错误。
`--fail-on <SEVERITY>`、`--format text|json|sarif|markdown`、`--no-color`。

---

## 11. 测试策略（对应需求 §21.10）

1. **规则 → 测试一一映射**：新增 rule 时 CI 强制新增对应测试函数（`rule_registry.rs` 内计数断言）。
2. **fixtures 四象限**：safe（零 finding）/ malicious（必须命中）/ suspicious（有 evidence 不升级）/
   obfuscated（必须被归一化后命中）/ edge_cases（不得 panic）。
3. **黄金输出**：`tests/golden/` 快照 text 与 json 输出，防无意变更破坏用户 CI。
4. **哈希确定性测试**：同一内容两次运行 digest 相同；改一个字节必须变化。
5. **不变量测试**：deny 时 agent 目录零写入（用临时目录 + 断言文件系统未变）。
6. **property test**（可选，`proptest`）：任意文本输入不得 panic。

---

## 12. CI 与发布

- `cargo fmt --check` / `cargo clippy -- -D warnings` / `cargo test` / `cargo deny check`
- 最低支持 Rust 版本固定；提供预编译二进制（linux x86_64/arm64、macOS、windows）+ `install.sh`
- 后续 GitHub Action：`skillguard action@v1`，读取 SARIF 上传 Code Scanning，违规 exit 1

## 13. 明确不做（架构层记录）

Web Registry / SaaS / LLM / Agent Runtime / Autonomous Security Agent / 远程扫描服务 /
自研模型 / MCP 全生态扫描 / 分布式调度。