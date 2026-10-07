# SkillGuard

> **A local-first package manager and supply-chain security layer for AI Agent Skills.**
> npm-style package management for Agent Skills — with a trust gate before install.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

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

## Design constraints

1. **Zero LLM in the core.** Every verdict is deterministic — regex, AST, YAML
   parser, SHA256, SPDX, git. No model is called, ever.
2. **Fully offline.** Scanning uploads nothing anywhere. Your skills never leave
   your machine.
3. **The scanner never executes what it scans.** No `npm install`, no
   `subprocess` on scanned files, no network. The scanned skill is hostile input.
4. **Evidence, not verdicts.** Every finding carries `file`, `line`, and the
   original text. No evidence, no finding.
5. **Single Rust binary.** No Node, no Python, no runtime deps in CI.

## Status

Research and architecture complete. See [docs/](docs/).

- [**Feasibility, Direction & GTM**](docs/VIABILITY.md) — **read this first.**
  Market data, why "package manager" is the wrong framing, where the real gap is,
  and the phased go-to-market plan.
- [**Phase 0 Corpus Study**](docs/PHASE0_CORPUS_STUDY.md) — the plan to produce the
  first large-scale empirical measurement of the skill ecosystem. High visibility,
  near-zero cost, and it becomes our permanent regression benchmark.
- [Competitive Analysis](docs/COMPETITIVE_ANALYSIS.md) — 13 projects surveyed,
  what each already does, and where the gaps actually are
- [Architecture](docs/ARCHITECTURE.md) — crate layout, data flow, invariants
- [Threat Model](docs/THREAT_MODEL.md) — T1–T16, including attacks on the scanner
- [MVP Roadmap](docs/MVP.md) — phased scope with exit criteria

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
| **0** | 100k-skill corpus study, public dataset, benchmark | planned |
| 1 | Parser, finding model, scanner | planned |
| 2 | Capability model, declared vs observed | planned |
| 3 | Policy engine, approval lockfile | planned |
| 4 | CI / SARIF / GitHub Action / rule registry | planned |
| 5 | `add` / `install` — **optional**, only on demonstrated demand | deferred |

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