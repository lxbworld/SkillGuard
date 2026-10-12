# Agent Skill Package Security / Supply Chain

## 1. Project goal

Design and implement an open-source package security / supply-chain tool for AI Agent Skills.

The core positioning:

> **The npm + npm audit + package-lock + supply-chain security of Agent Skills.**

Do not position the project as:

* Yet another Skill Registry
* Yet another Skill Directory
* Yet another simple Skill Linter
* Yet another Snyk Agent Scan clone

The goal is to build Agent Skills'

**Package → Verify → Scan → Policy → Trust → Lock → Install**

complete chain.

---

# 2. Why this direction

Agent Skills are rapidly forming a distribution model like that of a software package ecosystem.

A Skill is essentially becoming:

```text
SKILL.md
+ scripts/
+ dependencies
+ external URLs
+ package manager commands
+ permissions
```

It is not merely Markdown.

A Skill can affect:

* filesystem
* shell
* network
* secrets
* credentials
* APIs
* package installation
* external downloads
* agent instructions

So it inherently carries software supply-chain risk.

What already exists:

* Snyk Agent Scan
* SkillMD
* SkillPreflight
* skil
* skillpm
* skills.sh
* Various Skill registries

But these projects' capabilities are still fairly scattered.

Our goal is not to build another registry, but to combine:

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

into one unified Agent Skill trust layer.

---

# 3. The most important cost constraint

This is a very important design principle for the project.

## Development phase

By default use only:

> DeepSeek

Do not design anything that needs:

* GPT
* Claude
* Gemini
* Qwen
* DeepSeek

a workflow in which several models take part in development or testing at the same time.

The Coding Agent should be able to complete the main development with a single model.

---

## Product runtime phase

Core functionality:

> **Depending on an LLM is forbidden.**

Every core security judgement prefers deterministic/static analysis.

For example:

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

An LLM is allowed only as a future Optional Semantic Analyzer.

That is:

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

The MVP does not need AI.

---

# 4. Core product concepts

A provisional project name:

```text
agentpkg
```

or:

```text
agent-trust
```

Do not rush the final name.

The core command is something like:

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

# 5. The core user flow

The target experience:

```bash
agentpkg add github:user/financial-analysis
```

The system performs:

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

The user can:

```bash
agentpkg approve
```

Then:

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

# 6. What the MVP does not do

This is very important.

The first phase must not expand its scope.

Do not do:

* Web Registry
* SaaS Dashboard
* Multi-model benchmarks
* Agent Eval
* Agent Runtime
* Autonomous Security Agent
* Enterprise MDM
* A large-scale cloud scanning platform
* Training your own model
* LLM-based security judgement
* Scanning the whole MCP ecosystem

In particular, do not start with:

```text
skills.sh clone
```

Nor start with:

```text
Snyk clone
```

---

# 7. The MVP's first phase

The first phase does only:

## A. Skill Parser

Input:

```text
SKILL.md
```

and:

```text
scripts/
references/
assets/
```

Parsing:

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

Detect what capabilities a Skill has.

For example:

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

The key point:

**Capability detection must be deterministic.**

---

# 8. Security Scanner

The MVP detects at least:

### Secrets

* API keys
* tokens
* passwords
* private keys
* environment variables
* credential files

---

### Shell

For example:

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

Do not simply see a command and call it malicious.

The output should be:

```text
Risk:
shell.execution

Evidence:
SKILL.md:42

Command:
curl ...
```

That is:

> Give evidence, not just a verdict.

---

### Network

Detect:

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

Detect:

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

and:

* absolute paths
* home directory access
* recursive filesystem access

---

### Downloads

Detect:

```text
curl URL | sh
wget URL
download executable
download archive
install binary
```

Pay particular attention to:

```text
download → execute
```

chains like this.

---

### Prompt Injection

The MVP does only deterministic heuristics.

For example, detect:

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

and:

* base64
* Unicode obfuscation
* hidden text
* suspicious instruction patterns

Do not try to make an LLM decide "is this prompt injection".

---

# 9. Risk Model

Do not simply:

```text
safe / unsafe
```

The recommended output:

```text
Risk Level:
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Every finding:

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

This is a very important potential differentiator for the project.

Let a Skill declare:

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

Then the scanner obtains:

```text
DECLARED
vs
OBSERVED
```

For example:

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

Compare this with merely reporting:

```text
"this Skill has network access"
```

which is all a bare flag can give you.

---

# 11. Policy Engine

Let the user define:

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

Perform:

```bash
agentpkg policy check ./skill
```

Output:

```text
Policy violation:

network.outbound
shell.execute
filesystem.read(~/.ssh)

Installation blocked.
```

---

# 12. Provenance

Every Skill should record:

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

For example:

```yaml
provenance:
  source: github
  repository: user/skill
  commit: abc123
  digest: sha256:...
  license: MIT
```

The core principle:

> Do not trust the repository URL alone.

It must be bound to:

```text
source
+
commit
+
content hash
```

---

# 13. Lockfile

Design:

```text
agentpkg.lock
```

For example:

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

Later:

```bash
agentpkg install
```

Installation must follow the lockfile.

The goal:

> Installing the same Skill for the same project on different machines yields identical content.

---

# 14. Trust Score

It can do:

```text
Agent Trust Score
```

But do not make it the only verdict.

For example:

```text
Security       82
Permissions    65
Provenance     95
Maintainability 72
Compatibility  90
License        100

Overall         82
```

At the same time it must show:

```text
WHY
```

rather than showing only:

```text
82/100
```

---

# 15. CI/CD

Later it supports:

```yaml
GitHub Action
```

For example:

```text
agentpkg scan
agentpkg policy check
```

Failure:

```text
exit 1
```

Output:

* JSON
* Markdown
* SARIF

That is how it reaches GitHub Security / Code Scanning.

---

# 16. Relationship to competitors

The main competitors / reference points today:

### Snyk Agent Scan

Strengths:

* Agent/MCP/Skill security
* enterprise
* threat research
* Automatic discovery
* Risk analysis

Do not copy them head-on.

Our difference:

> Developer-first package/supply-chain workflow

That is:

```text
install
→ verify
→ scan
→ policy
→ lock
```

rather than:

```text
discover machine
→ scan machine
→ enterprise monitoring
```

---

### SkillMD

Already covers:

* Skill registry
* lint
* capability detection
* security scan integration

Its capability scan emphasises deterministic, no model calls.

So do not stop at:

```text
skill lint
```

It must go further, to:

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

Already provides:

* pre-install scan
* security
* permissions
* token cost
* maintainability
* CLI
* GitHub Action
* policy

And it explicitly states that it does not execute the scanned Skill.

So do not simply copy the scorecard.

Our focus should be:

> package lifecycle + integrity + lockfile + policy enforcement

---

### skills.sh

Strengths:

* discovery
* installation
* ecosystem
* leaderboard

Do not build a clone of it.

We can treat it as a future registry source, not as the core we compete with.

---

# 17. The product model we actually want to build

In the end we want to form:

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

# 18. Technology recommendations

Prefer:

```text
Python
```

because:

* Users are familiar with it
* The security tooling is rich
* Tree-sitter support is good
* CLI development is convenient
* It is easy to connect to Semgrep/YARA later
* A DeepSeek Coding Agent can maintain it easily

CLI:

```text
Typer
```

Data model:

```text
Pydantic
```

Parsing:

```text
PyYAML
Markdown parser
Tree-sitter
```

Hash:

```text
SHA256
```

License:

```text
SPDX
```

Testing:

```text
pytest
```

Output:

```text
Rich
```

Later it can add:

```text
SARIF
JSON
Markdown
```

---

# 19. Repository structure

Keep it clear from the start:

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

# 20. First-phase development order

Do not implement everything at once.

### Phase 1

```text
Skill parser
+
finding model
+
basic scanner
```

Supports:

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

Then consider:

```text
registry
search
publish
trust badges
```

---

# 21. Development principles for the Coding Agent

This is a very important part of the project.

The Coding Agent must follow these:

1. Do not introduce an LLM API as a core dependency.
2. Do not call several models in order to test.
3. Do not add unnecessary SaaS/APIs.
4. Offline/local-first by default.
5. The scanner does not execute a scanned Skill.
6. Trust no code inside a Skill.
7. Test fixtures must include malicious/dangerous samples.
8. Every security finding must have evidence.
9. Be deterministic wherever possible.
10. Every security rule added comes with its regression test.
11. Prefer small modules and clear interfaces.
12. Do not pre-design a complex distributed architecture for a "future need".

---

# 22. The most important security principles

The scanner itself must follow:

> **Treat the scanned Skill as hostile input.**

Therefore:

```text
SKILL.md
scripts/
package.json
requirements.txt
URLs
commands
```

All of this belongs to:

```text
UNTRUSTED INPUT
```

The scanner should not:

```text
execute scripts
run npm install
run pip install
execute shell commands
load environment secrets
connect to arbitrary network
```

unless an isolated sandbox is explicitly provided in future.

---

# 23. MVP success criteria

The first version is not about how many features it has.

But about:

```text
agentpkg scan suspicious-skill
```

reliably finding:

* credential access
* shell execution
* filesystem access
* network access
* suspicious download
* prompt injection
* dangerous dependencies

and:

```text
agentpkg policy check
```

It can block a Skill that violates the organisation's policy.

Then:

```text
agentpkg verify
```

It can confirm:

```text
source
+
commit
+
hash
```

Finally:

```text
agentpkg install
```

It can install from:

```text
verified package
+
policy
+
lockfile
```

and perform an installation.

---

# 24. Final product positioning

In one sentence:

> **A local-first package manager and supply-chain security layer for AI Agent Skills.**

A simpler tagline:

> **npm-style package management and supply-chain security for Agent Skills.**

The core is not:

```text
AI
```

but:

```text
Trust
```

The core is not:

```text
Which model is smarter?
```

but:

```text
What exactly am I installing?
What can it access?
Where did it come from?
Did it change?
Am I allowed to install it?
Can I reproduce the same installation?
```

---

# 25. The Coding Agent's first task now

Do not start writing code frantically.

First complete:

## Research + Architecture

Require the Coding Agent to:

1. Read deeply:

   * Snyk Agent Scan
   * SkillMD
   * SkillPreflight
   * skil
   * skillpm
   * skills.sh

2. Build a competitor matrix.

3. Establish clearly which capabilities someone already provides.

4. Find the genuinely unsolved problems in:

   * package management
   * provenance
   * lockfile
   * permissions
   * policy
   * capability verification

5. Output:

```text
docs/COMPETITIVE_ANALYSIS.md
docs/ARCHITECTURE.md
docs/THREAT_MODEL.md
docs/MVP.md
```

6. **Do not start large-scale implementation until these four documents are complete.**

7. Only then move on to Phase 1.

---

# 26. A very important judgement

If, after the research, it turns out that

```text
agentpkg
```

this direction has already been implemented completely by some project,

do not force it.

Keep looking further down for

```text
Agent Skill
Supply Chain
+
```

the infrastructure that is still missing.

Our goal is not:

> "to build an Agent project that looks cool."

It is:

> **To find the infrastructure gap in the Agent Skills ecosystem, of the same kind as npm / package-lock / npm audit / Sigstore.**

That is the direction most worth investing in for this project.
