# SkillGuard — Competitive Analysis

Research date: 2026-10-07. Every conclusion is based on public repositories,
documentation and official sites.

---

## 0. The one-line conclusion

**Nobody has built "npm + npm audit + package-lock" for Skills as a whole**, but
**every one of its pieces is already covered individually**, and one project
(`skil-lock`) has already turned "capability lockfile + policy + approval flow" into
a complete product. SkillGuard cannot sell itself on "we have a lockfile / a policy /
a scanner".

The differentiation has to land in three places:

1. **Declared vs Observed (verifying the permission declaration)** — nobody has a
   production-grade implementation.
2. **Deterministic, offline, network-free single binary (Rust)** — the existing
   options either depend on a cloud LLM (Snyk) or on a Node/Python runtime.
3. **The whole package lifecycle** — the existing projects' heavy assets are in the
   registry / discovery / ecosystem; installation is incidental.

---

## 1. The competitor matrix

| Project | Language/form | Core position | Lockfile | Policy | Scanner | Provenance | Needs network/LLM | License |
|---|---|---|---|---|---|---|---|---|
| **Snyk Agent Scan** | Python, uvx/binary | Machine-level discovery + threat analysis | ❌ | ❌ (enterprise MDM) | ✅ 14 risk classes | ❌ | **✅ cloud analysis API** | Apache-2.0 |
| **skillmds / SkillMD** | Node/TS, npm | A registry of 1.13M skills + lint | ✅ pinned commit | ❌ | ✅ capability flags (deterministic) | ✅ commit pin | ❌ (local) | MIT |
| **skill-preflight** | Node, npx | Pre-install scorecard | ❌ | ✅ JSON policy + fail-on | ✅ 100-point scale | ❌ | ❌ | MIT |
| **SkillSpector (NVIDIA)** | Python + uv | Scanner (Tier 1) | ❌ | ✅ triage table | ✅ static + optional LLM | ❌ | optional | see repo |
| **skills (vercel-labs, skills.sh)** | Node, npx | Ecosystem-level installer + leaderboard | ✅ skills-lock.json | ❌ | ❌ | ✅ hash/folder hash | partly | MIT |
| **skil-lock** | Go | **Capability-surface locking + PR approval** | ✅ skills.lock (SPEC) | ✅ YAML + approvals | ✅ | ✅ content_hash | ❌ | Apache-2.0 |
| **skillpkg/spm** | Go + frontend | Private registry + Sigstore signing | ✅ skills-lock.json | ❌ | ✅ 3 layers | ✅ Sigstore | ✅ registry | MIT |
| **skillpm** | Node | npm-native package manager | ✅ reuses npm | ❌ | scans node_modules for skills | ✅ npm | ✅ npm | MIT |
| **skills-package-manager** | Node | Single-file manifest pinning a commit | ✅ skills.json | ❌ | ❌ | ✅ commit | ❌ | see repo |
| **skill** (crates.io) | **Rust library** | An embedding framework for the Skill ecosystem | ✅ two lockfiles | ❌ | ❌ | ✅ | partly | see crates.io |
| **AgentBound / SkillGuard (arXiv)** | academic | Permission framework + runtime enforcement | ✅ manifest | ✅ | — | — | needs a sandbox | paper |

> ⚠️ **Name-collision warning**: arXiv `2606.03024` already proposes **SkillGuard: A
> Permission Framework for Agent Skills** (an Android-style permission manifest, 91.0%
> F1 manifest generation). Another paper, `2605.10990`, has a same-named system doing
> skill drift monitoring. This repository shares the name. The recommendation is to
> keep SkillGuard but **cite and distinguish both papers in the README**, so it is not
> mistaken for an official implementation.

---

## 2. Each project in detail

### 2.1 Snyk Agent Scan

- **Strengths**: deep threat research (analysis of a 4000-skill corpus), 14 risk
  classes, both MCP and Skill coverage, MDM background scanning, a CI mode.
- **The fatal flaw (in our favour)**: `--analysis-url` points at the Snyk analysis
  API. **It is cloud-LLM-driven**; no verdict is produced locally. The official
  documentation repeatedly states that the CLI output is "experimental and may change
  at any time", and does not recommend depending on its issue codes in production.
- **The lesson for us**: offline deterministic scanning is a real and unoccupied
  position. Enterprises also have a natural unease about uploading Skills to a third
  party.

### 2.2 skillmds / SkillMD

- **Strengths**: scale (1.13M skills), 8 lint rules, a capability scanner that is
  explicitly "deterministic, no model needed, single file <1s", an MCP server, a
  GitHub Action, SARIF. **Its rules are open and readable**, which is a smart move.
- **Its own weakness**: its site reports that of 860,246 skills only 51.9% have
  capability flags and 4.5% have third-party scan results. Its `add` is "lint first,
  never executes scripts" — **the scan is not a gate on install**, and there is no
  policy block.
- **The lesson for us**: capability flags ≠ verifying a permission declaration. It has
  flags, but no declared-vs-observed diff.

### 2.3 skill-preflight

- **Strengths**: policy (`failBelow` / `failOn` / `ignoreRules` / `exclude`), SARIF, a
  GitHub Action, `--installed` discovery, a published benchmark methodology, and a
  companion skill for agents.
- **Weakness**: the core output is **one score**. Its documentation explicitly argues
  against copying the scorecard, and we should not copy it either. No lockfile, no
  provenance, no install.

### 2.4 skil-lock — the competitor to watch most closely

**Apache-2.0 / Go. It has already done "capability-surface lock + policy + approval +
CI gate"**:

- `skills.lock` records `shell_commands` / `network_urls` / `file_reads` / `file_writes`
  / `allowed_tools` / `bundled_scripts` plus a per-file `script_hashes`.
- A `.skil-lock.yaml` policy (protected_paths / allowed_domains / tiered severities).
- A `.skil-lock-approvals.yaml` approval audit (reviewer + reason + timestamp, which
  can be PR-scoped to prevent "re-approving after a re-introduction").
- `skil-lock ci` emits a PR comment + SARIF, and `skil-lock diff` compares two snapshots.
- There is a formal SPEC.md (v0.1, CC BY 4.0).
- Its own comparison table names Snyk Agent Scan and Mondoo Skills Check as
  "pre-install scanners".

**What it does not do**:
1. **Declared vs Observed**: it only records observed; it **does not verify the
   permissions the Skill itself declares**.
2. **Content-addressed provenance**: content_hash only detects drift; it does not do a
   source+commit+digest triple binding.
3. **An installer**: it is a post-install PR workflow, not a package manager.
4. **The ecosystem**: it does not install a skill into each agent directory.

### 2.5 vercel-labs/skills (npm `skills`, 7.24M weekly downloads)

- **Strengths**: the de-facto ecosystem standard, 72+ agents, `.skill-lock.json`
  (global) plus `skills-lock.json` (per project, with `computedHash` and a GitHub tree
  SHA folder hash), an MCP server.
- **Weakness**: **no security dimension at all**. That is the biggest opening — the
  installer with the largest install base has no policy gate whatsoever.
- A known bug: a local source writes an absolute path into the lockfile (issue #561),
  which is not reproducible across machines.

### 2.6 skillpkg/spm

- 3 layers of security scanning + **Sigstore signing** + a private registry.
- It proves that "signing + registry" is viable, but it is **registry-first**, which
  conflicts with a "local-first" position, and it requires trusting skillpkg.dev.

### 2.7 The crates.io `skill` crate

A Rust implementation already exists (v0.8.3), providing discovery/install/lockfile/
provider/sanitize. **It is not a security tool.** But it shows that "Rust + Skills" is
entirely workable, and that there is potential reuse and interoperability.

---

## 3. Capability coverage vs our goals

Of the 6 capabilities the requirements define, who owns each one:

| Capability | Already done by | Empty? |
|---|---|---|
| Package management | skills, skillpm, spm | ❌ not empty |
| Scan | Snyk, SkillMD, preflight, SkillSpector | ❌ not empty |
| Provenance | skills (hash), spm (Sigstore) | ⚠️ partly empty (no unified triple binding) |
| Lockfile | skills, skills-lock, skil-lock | ❌ not empty |
| Policy | skil-lock, preflight, AgentBound (paper) | ⚠️ partly empty (policy ≠ permission verification) |
| **Capability declaration verification (Declared vs Observed)** | **only the arXiv SkillGuard paper** | ✅ **entirely empty** |
| **An offline deterministic full chain (scan+policy+install in one run)** | **nobody** | ✅ **entirely empty** |
| **Cross-scanner composition / a unified evidence model** | SkillMD stores third-party results, but does not compose them | ✅ **entirely empty** |

---

## 4. The three genuinely unsolved problems (our footing)

### Problem 1: a Skill's declared permissions are never verified

Android's core insight is that **a manifest is a contract the system can check**.
Every tool today either:
- only observes (observed), or reads the declaration without verifying it.
- **No tool answers: "this Skill declares `network: api.example.com`, but its code also
  reaches `evil.example.com`, therefore refuse to install."**

That is the core of our Phase 2, and it is the moat. The academic SkillGuard generates
a manifest with an LLM (91% F1); we use **deterministic derivation + an explicit
declaration + a diff**, with zero LLM.

### Problem 2: observation is discrete, blocking is absent

- `skil-lock` blocks at PR time, but the skill is already installed on the machine.
- `skills` / `skillpm` do not block at install time; scanning is a separate command run
  afterwards.
- **No tool makes `scan → policy → block/approve → install` one atomic flow backed by a
  lockfile.**

The `agentpkg add github:user/financial-analysis` experience of requirements §5 has no
equivalent in the industry.

### Problem 3: the loop on reproducible installation is incomplete

`skills-lock.json` has a hash but no commit (the skillpm docs note that
`package-lock.json` is npm's source of truth while skill tracking lives in
`skills-lock.json`); `skills-lock` has a commit but no policy. **No single lockfile
contains: source + commit + content digest + declared permissions + observed
capabilities + policy decision.**

---

## 5. The relationship to "SkillGuard (arXiv)" — handled honestly

What that paper does: Skill Manifest + baseline policy + session state + runtime
enforcement (which needs a sandbox), validated on 315 real skills with 99.76%
permission-taxonomy coverage and 91.0% F1 on automatic manifest generation.

**Our relationship to it should be complementary, not competitive**:
- It works on **runtime enforcement** (needs a sandbox, which we explicitly do not do).
- We work on **pre-install verification** (no sandbox, offline, local-first).

The recommendation: cross-cite in the README and the paper, stating clearly that "this
project is a pre-install, LLM-free, purely static implementation of the permission
manifest idea from the SkillGuard paper". That builds credibility better than
contesting the name, and avoids the awkwardness of the collision.

---

## 6. Positioning (one sentence, usable directly in the README)

> SkillGuard is **a package manager + trust layer for the Skill ecosystem**:
> it is the **only** tool that **diffs declared permissions against observed
> capabilities** *before* installation and blocks installation with a **declarative
> policy + an approval lockfile**; its core judgement is **fully deterministic, offline,
> a single Rust binary, no LLM, no cloud**.

The one-sentence comparisons:
- Not Snyk (we are offline, upload nothing, and block installation)
- Not SkillMD (we are not a registry; we have policy blocking and a lockfile)
- Not skil-lock (we add declared-vs-observed, installation, and provenance)
- Not skills/spm (they do not handle security; we do not handle the ecosystem)

---

## 7. Risks and the stop-loss point

| Risk | Response |
|---|---|
| `skil-lock` adds declared-vs-observed quickly | Publish the paper/spec first to hold the slot; spec first, draft a `SKILLGUARD.lock` spec and release it under CC BY |
| The arXiv SkillGuard takes the name | Cite it proactively and state the complementarity; consider distinguishing with a product name (see the "naming" section of MVP.md) |
| The ecosystem is locked into skills (7M/week) | Provide `skills-lock.json` → `SKILLGUARD.lock` **reading and migration**; be a supplement, not a replacement |
| Being misread as "yet another skill linter" | The first-screen demo must be `add → scan → policy block → approve → lockfile`, not `lint` |
| Immature tree-sitter bindings in the Rust ecosystem | The MVP uses regex + YAML/JSON parsers (deterministic is enough); tree-sitter is an optional enhancement |

**Stop-loss condition**: if Phase 2 (declared-vs-observed) cannot reach an acceptable
precision while staying deterministic, fall back to Phase 1 as "the best offline
evidence-grade scanner + policy blocking", which is still a standalone product.
