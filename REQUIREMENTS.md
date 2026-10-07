# Agent Skill Package Security / Supply Chain

## 1. 项目目标

设计并实现一个面向 AI Agent Skills 的开源 Package Security / Supply Chain 工具。

核心定位：

> **Agent Skills 的 npm + npm audit + package-lock + supply-chain security。**

不要把项目定位成：

* 又一个 Skill Registry
* 又一个 Skill Directory
* 又一个简单 Skill Linter
* 又一个 Snyk Agent Scan clone

目标是建立 Agent Skill 的：

**Package → Verify → Scan → Policy → Trust → Lock → Install**

完整链路。

---

# 2. 为什么做这个方向

Agent Skills 正在快速形成类似软件包生态的分发模式。

一个 Skill 本质上已经越来越接近：

```text
SKILL.md
+ scripts/
+ dependencies
+ external URLs
+ package manager commands
+ permissions
```

它不是单纯的 Markdown。

Skill 可能影响：

* filesystem
* shell
* network
* secrets
* credentials
* APIs
* package installation
* external downloads
* agent instructions

因此它天然存在 Software Supply Chain 风险。

当前已经出现：

* Snyk Agent Scan
* SkillMD
* SkillPreflight
* skil
* skillpm
* skills.sh
* 各种 Skill Registry

但这些项目的能力仍然比较分散。

我们的目标不是重新做一个 Registry，而是把：

```text
Package Management
+
Security
+
Provenance
+
Permissions
+
Policy
+
Lockfile
```

组合成一个统一的 Agent Skill Trust Layer。

---

# 3. 最重要的成本约束

这是本项目非常重要的设计原则。

## 开发阶段

默认只使用：

> DeepSeek

不要设计需要：

* GPT
* Claude
* Gemini
* Qwen
* DeepSeek

多模型同时参与开发或测试的工作流。

Coding Agent 应该能够使用单一模型完成主要开发。

---

## 产品运行阶段

核心功能：

> **禁止依赖 LLM。**

所有核心安全判断优先使用 deterministic/static analysis。

例如：

* Tree-sitter
* AST
* Regex
* YAML parser
* JSON Schema
* Git
* SHA256
* SPDX
* Semgrep/YARA
* dependency parser
* URL/domain parser
* filesystem path analysis
* shell command analysis

LLM 只允许作为未来的 Optional Semantic Analyzer。

即：

```text
                Agent Trust
                     |
        +------------+------------+
        |                         |
 Deterministic Layer       Optional AI Layer
        |                         |
 AST / Tree-sitter          DeepSeek
 Regex                      semantic analysis
 SHA256                     explanation
 Git                        suspicious intent
 Policy
 Permissions
```

MVP 不需要 AI。

---

# 4. 产品核心概念

建议暂定项目名称：

```text
agentpkg
```

或者：

```text
agent-trust
```

最终名称暂时不要急着决定。

核心命令类似：

```bash
agentpkg scan ./my-skill

agentpkg inspect ./my-skill

agentpkg verify ./my-skill

agentpkg add github:user/skill

agentpkg install

agentpkg update

agentpkg lock

agentpkg policy check
```

---

# 5. 核心用户流程

目标体验：

```bash
agentpkg add github:user/financial-analysis
```

系统执行：

```text
Resolving skill...

✓ Git source detected
✓ Commit pinned
✓ SHA256 calculated
✓ License detected
✓ Dependencies detected

Security
────────────────────
✓ No hardcoded credentials
⚠ Network access
⚠ Shell execution
✓ No suspicious downloads
✓ No obvious prompt injection
✓ No known malicious dependency

Permissions
────────────────────
network:
  api.example.com


filesystem:
  ./data/**

shell:
  python

secrets:
  none

Policy
────────────────────
✗ Network access is not allowed

Installation blocked.
```

用户可以：

```bash
agentpkg approve
```

然后：

```text
Skill installed.

Integrity:
sha256: ...

Source:
github:user/financial-analysis

Commit:
abc123...

Permissions:
network
filesystem

Lockfile updated.
```

---

# 6. MVP 不做什么

非常重要。

第一阶段禁止扩大范围。

不要做：

* Web Registry
* SaaS Dashboard
* 多模型 Benchmark
* Agent Eval
* Agent Runtime
* Autonomous Security Agent
* 企业级 MDM
* 大规模云端扫描平台
* 自己训练模型
* LLM-based security judgement
* MCP 全生态扫描

尤其不要一开始做：

```text
skills.sh clone
```

也不要一开始做：

```text
Snyk clone
```

---

# 7. MVP 第一阶段

第一阶段只做：

## A. Skill Parser

输入：

```text
SKILL.md
```

以及：

```text
scripts/
references/
assets/
```

解析：

* name
* description
* metadata
* dependencies
* scripts
* URLs
* commands
* permissions
* referenced files

---

## B. Capability Detection

检测 Skill 具有什么能力。

例如：

```yaml
capabilities:

  filesystem:
    read: true
    write: true

  shell:
    execute: true

  network:
    outbound: true

  secrets:
    read: false

  package_install:
    npm: true
    pip: false
```

重点：

**Capability detection 必须 deterministic。**

---

# 8. Security Scanner

MVP 至少检测：

### Secrets

* API keys
* tokens
* passwords
* private keys
* environment variables
* credential files

---

### Shell

例如：

```text
curl
wget
bash
sh
chmod
sudo
rm
eval
exec
python -c
node -e
```

不要简单地看到命令就判定 malicious。

输出应该是：

```text
Risk:
shell.execution

Evidence:
SKILL.md:42

Command:
curl ...
```

即：

> 给证据，而不是简单给 verdict。

---

### Network

检测：

* HTTP/HTTPS
* curl
* wget
* fetch
* requests
* axios
* socket
* external domains

---

### Filesystem

检测：

```text
~/.ssh
~/.aws
~/.config
.env
.git/
credentials
tokens
private keys
```

以及：

* absolute paths
* home directory access
* recursive filesystem access

---

### Downloads

检测：

```text
curl URL | sh
wget URL
download executable
download archive
install binary
```

尤其关注：

```text
download → execute
```

这样的 chain。

---

### Prompt Injection

MVP 只做 deterministic heuristic。

例如检测：

```text
ignore previous instructions
ignore all previous instructions
system message
do not tell the user
hidden instructions
send the contents of
reveal credentials
API key
environment variables
```

以及：

* base64
* Unicode obfuscation
* hidden text
* suspicious instruction patterns

不要试图让 LLM 判断“这是不是 prompt injection”。

---

# 9. Risk Model

不要简单：

```text
safe / unsafe
```

建议输出：

```text
Risk Level:
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

每个 finding：

```json
{
  "rule": "SECRET_ENV_ACCESS",
  "severity": "HIGH",
  "file": "SKILL.md",
  "line": 42,
  "evidence": "...",
  "capability": "secrets.read",
  "confidence": "high"
}
```

---

# 10. Capability Manifest

这是项目非常重要的潜在差异化方向。

允许 Skill 声明：

```yaml
permissions:

  filesystem:
    read:
      - "./data/**"

  network:
    outbound:
      - "api.example.com"

  shell:
    execute:
      - "python"

  secrets:
    access: false
```

然后 Scanner 得到：

```text
DECLARED
vs
OBSERVED
```

例如：

```text
Declared:

network:
  api.example.com

Observed:

network:
  api.example.com
  evil.example.com

Mismatch:

HIGH
Unexpected network destination:
evil.example.com
```

这比单纯：

```text
"这个 Skill 有 network access"
```

更有价值。

---

# 11. Policy Engine

允许用户定义：

```yaml
policy:

  network:
    allow: false

  shell:
    allow: false

  secrets:
    allow: false

  filesystem:
    allow:
      - "./data/**"
```

执行：

```bash
agentpkg policy check ./skill
```

输出：

```text
Policy violation:

network.outbound
shell.execute
filesystem.read(~/.ssh)

Installation blocked.
```

---

# 12. Provenance

每个 Skill 都应该记录：

```text
source
repository
commit
author
version
license
sha256
timestamp
```

例如：

```yaml
provenance:
  source: github
  repository: user/skill
  commit: abc123
  digest: sha256:...
  license: MIT
```

核心原则：

> 不要只信 repository URL。

必须绑定：

```text
source
+
commit
+
content hash
```

---

# 13. Lockfile

设计：

```text
agentpkg.lock
```

例如：

```yaml
skills:

  financial-analysis:
    source: github:user/financial-analysis
    commit: abc123
    sha256: ...
    version: 1.2.0

    permissions:
      network:
        - api.example.com

    dependencies:
      - python:pandas
```

以后：

```bash
agentpkg install
```

必须按照 lockfile 安装。

目标：

> 同一个项目在不同机器上安装同一个 Skill，得到相同内容。

---

# 14. Trust Score

可以做：

```text
Agent Trust Score
```

但不要把它作为唯一 verdict。

例如：

```text
Security       82
Permissions    65
Provenance     95
Maintainability 72
Compatibility  90
License        100

Overall         82
```

同时必须展示：

```text
WHY
```

而不是只显示：

```text
82/100
```

---

# 15. CI/CD

后续支持：

```yaml
GitHub Action
```

例如：

```text
agentpkg scan
agentpkg policy check
```

失败：

```text
exit 1
```

输出：

* JSON
* Markdown
* SARIF

这样可以进入 GitHub Security / Code Scanning。

---

# 16. 与竞品的关系

目前主要竞品/参考对象：

### Snyk Agent Scan

强项：

* Agent/MCP/Skill security
* enterprise
* threat research
* 自动发现
* 风险分析

不要正面复制。

我们的区别：

> Developer-first package/supply-chain workflow

即：

```text
install
→ verify
→ scan
→ policy
→ lock
```

而不是：

```text
discover machine
→ scan machine
→ enterprise monitoring
```

---

### SkillMD

已经覆盖：

* Skill registry
* lint
* capability detection
* security scan integration

其 capability scan 强调 deterministic、不依赖模型调用。

所以不要只做：

```text
skill lint
```

必须进一步做到：

```text
package
+
provenance
+
lockfile
+
policy
+
installation
```

---

### SkillPreflight

已经提供：

* pre-install scan
* security
* permissions
* token cost
* maintainability
* CLI
* GitHub Action
* policy

而且明确强调不执行被扫描 Skill。

因此不要简单复制 scorecard。

我们的重点应该是：

> package lifecycle + integrity + lockfile + policy enforcement

---

### skills.sh

强项：

* discovery
* installation
* ecosystem
* leaderboard

不要做它的 clone。

我们可以把它当成未来 registry source，而不是竞争核心。

---

# 17. 真正想建立的产品模型

最终希望形成：

```text
                 Agent Skill Ecosystem
                          │
             ┌────────────┴────────────┐
             │                         │
         Discovery                  Package
             │                         │
        skills.sh                  agentpkg
                                       │
                  ┌────────────────────┼─────────────────┐
                  │                    │                 │
                Verify               Scan              Policy
                  │                    │                 │
               SHA256              Security          Permission
               Commit              Secrets            Rules
               Provenance          Network            Allow/Deny
                                   Shell
                  │                    │
                  └────────────────────┼─────────────────┘
                                       │
                                   Lockfile
                                       │
                                    Install
```

---

# 18. 技术选型建议

优先：

```text
Python
```

因为：

* 用户熟悉
* Security tooling 丰富
* Tree-sitter 支持好
* CLI 开发方便
* 后续容易接 Semgrep/YARA
* DeepSeek Coding Agent 容易维护

CLI：

```text
Typer
```

数据模型：

```text
Pydantic
```

解析：

```text
PyYAML
Markdown parser
Tree-sitter
```

Hash：

```text
SHA256
```

License：

```text
SPDX
```

测试：

```text
pytest
```

输出：

```text
Rich
```

以后可以增加：

```text
SARIF
JSON
Markdown
```

---

# 19. Repository 结构

建议从一开始保持清晰：

```text
agentpkg/
│
├── src/
│   └── agentpkg/
│       ├── cli/
│       ├── parser/
│       ├── manifest/
│       ├── scanner/
│       │   ├── secrets/
│       │   ├── shell/
│       │   ├── network/
│       │   ├── filesystem/
│       │   ├── download/
│       │   └── prompt_injection/
│       │
│       ├── capabilities/
│       ├── policy/
│       ├── provenance/
│       ├── lockfile/
│       ├── installer/
│       └── models/
│
├── tests/
│   ├── fixtures/
│   │   ├── safe/
│   │   ├── malicious/
│   │   ├── suspicious/
│   │   └── edge_cases/
│   │
│   ├── test_parser.py
│   ├── test_scanner.py
│   ├── test_policy.py
│   └── test_lockfile.py
│
├── docs/
├── examples/
├── pyproject.toml
└── README.md
```

---

# 20. 第一阶段开发顺序

不要一次实现全部。

### Phase 1

```text
Skill parser
+
finding model
+
basic scanner
```

支持：

```text
secrets
shell
network
filesystem
downloads
prompt injection heuristics
```

---

### Phase 2

```text
capability model
+
permission manifest
+
policy engine
```

---

### Phase 3

```text
Git provenance
+
SHA256
+
verification
+
lockfile
```

---

### Phase 4

```text
agentpkg add
agentpkg install
agentpkg update
```

---

### Phase 5

```text
GitHub Action
+
SARIF
+
JSON
+
CI policy
```

---

### Phase 6

再考虑：

```text
registry
search
publish
trust badges
```

---

# 21. Coding Agent 的开发原则

这是本项目非常重要的一部分。

Coding Agent 必须遵守：

1. 不引入 LLM API 作为核心依赖。
2. 不为了测试而调用多个模型。
3. 不添加不必要的 SaaS/API。
4. 默认 offline/local-first。
5. Scanner 不执行被扫描 Skill。
6. 不信任 Skill 中的任何代码。
7. 测试 fixture 必须包含恶意/危险样例。
8. 所有 security finding 必须有 evidence。
9. 尽可能 deterministic。
10. 每增加一个 security rule，都增加对应 regression test。
11. 优先小模块、清晰接口。
12. 不为了“未来可能需要”提前设计复杂分布式架构。

---

# 22. 最重要的安全原则

Scanner 自己必须遵循：

> **Treat the scanned Skill as hostile input.**

因此：

```text
SKILL.md
scripts/
package.json
requirements.txt
URLs
commands
```

全部属于：

```text
UNTRUSTED INPUT
```

Scanner 不应该：

```text
execute scripts
run npm install
run pip install
execute shell commands
load environment secrets
connect to arbitrary network
```

除非未来显式提供隔离 sandbox。

---

# 23. MVP 成功标准

第一版不是看功能多少。

而是：

```text
agentpkg scan suspicious-skill
```

能够稳定发现：

* credential access
* shell execution
* filesystem access
* network access
* suspicious download
* prompt injection
* dangerous dependencies

并且：

```text
agentpkg policy check
```

可以阻止违反组织 policy 的 Skill。

然后：

```text
agentpkg verify
```

能够确认：

```text
source
+
commit
+
hash
```

最后：

```text
agentpkg install
```

能够基于：

```text
verified package
+
policy
+
lockfile
```

进行安装。

---

# 24. 最终产品定位

一句话：

> **A local-first package manager and supply-chain security layer for AI Agent Skills.**

更简单的宣传语：

> **npm-style package management and supply-chain security for Agent Skills.**

核心不是：

```text
AI
```

而是：

```text
Trust
```

核心不是：

```text
Which model is smarter?
```

而是：

```text
What exactly am I installing?
What can it access?
Where did it come from?
Did it change?
Am I allowed to install it?
Can I reproduce the same installation?
```

---

# 25. 现在 Coding Agent 的第一项任务

不要直接开始疯狂写代码。

先完成：

## Research + Architecture

要求 Coding Agent：

1. 深入阅读：

   * Snyk Agent Scan
   * SkillMD
   * SkillPreflight
   * skil
   * skillpm
   * skills.sh

2. 建立 competitor matrix。

3. 明确哪些能力已经有人做。

4. 找出：

   * package management
   * provenance
   * lockfile
   * permissions
   * policy
   * capability verification

   中真正没有被解决的问题。

5. 输出：

```text
docs/COMPETITIVE_ANALYSIS.md
docs/ARCHITECTURE.md
docs/THREAT_MODEL.md
docs/MVP.md
```

6. **不要开始大规模实现，直到这四个文档完成。**

7. 然后再进入 Phase 1。

---

# 26. 一个非常重要的判断

如果研究之后发现：

```text
agentpkg
```

这个方向已经被某个项目完整实现，

不要硬做。

应该继续向下寻找：

```text
Agent Skill
Supply Chain
+
```

中仍然缺失的基础设施。

我们的目标不是：

> “做一个看起来很酷的 Agent 项目。”

而是：

> **找到 Agent Skills 生态里类似 npm / package-lock / npm audit / Sigstore 那样的基础设施空缺。**

这才是这个项目最值得投入的方向。
