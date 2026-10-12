# Phase 0 — Large-Scale Corpus Security Study

**Purpose**: before writing the product, establish the project on data that cannot be
argued with.
**Status**: the protocol is pre-registered; the collection pipeline is implemented and
tested (`skillguard corpus index|scan|stats|report|reproduce`, see `tests/corpus.rs`).
**Blocked on collection permission** (issue #5, `research/TERMS-REVIEW.md` /
`research/DISCLOSURE.md`), not on code.
**Technical prerequisite**: the Phase 1 scanner plus the implemented corpus driver mode.

---

## 0. Why this comes before the product

In this field, "the first large-scale empirical measurement" is the only asset that
gets you the HN front page and security-press coverage:

| Project | Where its recognition came from | Scale of exposure |
|---|---|---|
| Snyk | Audited 3,984 skills (2026-02) | A standalone report + a Snyk Labs experiment page |
| Socket.dev | Scanned 60,000+ skills on skills.sh | A blog post + a standalone site + finding the Mastra attack within 6 minutes |
| arXiv GitSkills (2608.10906) | A dataset of 3,797,117 files / 282,200 repositories | Academic citations |

It also settles three other things:

1. **The rules' real precision** — measured against a 100k real corpus rather than
   self-made fixtures
2. **Dataset ownership** — the corpus index itself becomes a citable public asset
   (GitSkills is already indexed by alphaXiv)
3. **A denominator** — figures like "17.4% of skills under-declare permissions" need a
   denominator we control ourselves

---

## 1. Research questions (falsifiable hypotheses)

**Main question R1**: the Agent Skill ecosystem exhibits large-scale, systematic
missing permission declarations and dangerous behaviour patterns.

**Sub-questions**:

| ID | Question | Metric |
|---|---|---|
| R1.1 | How many skills contain hardcoded credentials? | `SECRET_*` hit rate |
| R1.2 | How many skills contain a `download → execute` chain? | `DL_CHAIN_FETCH_EXECUTE` |
| R1.3 | How many skills run shell / escalate privileges / run destructive commands? | `SHELL_*` |
| R1.4 | How many skills access sensitive paths or environment variables? | `SECRET_PATH_READ` / `SECRET_ENV_DUMP` |
| R1.5 | How many skills contain deterministically detectable prompt injection? | `PI_*` |
| R1.6 | **How many skills declare permissions? Of those, how many under-declare?** | ⭐ the core differentiating metric |
| R1.7 | Which obfuscation techniques are actually used in the wild? | the `OBFUSC_*` distribution |
| R1.8 | What is the rate of divergence between declaration and actual behaviour? | declared vs observed |
| R1.9 | Are dependency declarations complete and version-pinned? | `DEP_*` |
| R1.10 | Does the license declaration match the actual LICENSE file? | `LICENSE_*` |

**Explicit non-goals (to stop the research drifting)**:
- ❌ Do not judge whether a skill "is malicious" (we report evidence only)
- ❌ Do not do semantic/intent determination
- ❌ Do not evaluate model capability
- ❌ Do not study MCP servers

---

## 2. Corpus sources and sampling

### 2.1 Source layers

| Layer | Source | How it is obtained | How it is sampled |
|---|---|---|---|
| L1 public registry | the skills.sh leaderboard / the skillmd.com API | Official public API, rate limits respected | Stratified by install count |
| L2 contested registry | ClawHub | Public index | **Everything** (known to contain malicious entries, high value) |
| L3 GitHub | `filename:SKILL.md` code search | GitHub REST API, authenticated | Random sampling + stratification |
| L4 academic dataset | GitSkills (arXiv 2608.10906) | Author request / public download | Reuse its repository metadata |
| L5 ecosystem directories | skillsmp, skillful.sh, awesome lists | Public | Random after deduplication |

**Target total**: N = 100,000 unique skills (deduplicated by content digest)

### 2.2 Stratified sampling

Stratification is mandatory, or the conclusions will be dominated by the "AI Tool"
category (69.7% of the corpus). The dimensions:

| Dimension | Strata |
|---|---|
| Source | L1 / L2 / L3 / L4 / L5 |
| Size | <8 KB · 8–32 KB · 32–128 KB · >128 KB |
| Contains scripts | no `scripts/` · shell · python · js/ts · other |
| Declares permissions | yes · no |
| License | has LICENSE · none · declaration conflicts with the file |
| Install count (L1 only) | Top 1% · 1–10% · 10–50% · 50–100% · tail |

**The sampling fraction for each stratum must be published** in the report, together
with **each stratum's N**. An over-capacity stratum (such as all of GitHub in L3) uses
**systematic sampling** (by repository ID hash modulo) rather than simple random
sampling, so that it is reproducible and unbiased.

### 2.3 Reproducibility (non-negotiable)

Every analysed skill records a triple:

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

**Requirements**:
- Tags / branches / short SHAs are rejected (the principle in architecture §7 applies to
  corpus collection too)
- `corpus-manifest.json` is committed into the repository's `research/` directory, so it
  can be diffed and reviewed
- `skillguard corpus reproduce <manifest>` reproduces the whole analysis
- The collection window (UTC) is recorded, because upstream repositories change

> **This is the most easily overlooked detail of this phase, and the one that most
> determines credibility.** Corpus research without pinned commits is worthless in
> security.

---

## 3. Compliance and ethics (before the technical work)

This is the biggest non-technical risk of the phase. **It must be finished before the
first line of scanning code is written.**

### 3.1 Hard rules

| Rule | Description |
|---|---|
| **R-1 Read only, never execute** | Never run, install, `npm install` or `pip install` a scanned skill. Archiving only stores bytes |
| **R-2 Do not redistribute malicious content** | A report publishes **only**: rule IDs, content digests, line numbers, and **redacted** evidence fragments (domains kept; private keys/credentials truncated). It does **not** publish a runnable payload |
| **R-3 Rate limiting** | Respect GitHub API limits strictly (5,000 req/h authenticated). A self-built throttle, 1 req/s by default, with exponential backoff and a 429 circuit breaker |
| **R-4 Respect robots.txt and ToS** | Each registry's ToS is reviewed line by line and recorded (in `research/TERMS-REVIEW.md`). A source that forbids collection is excluded, and the report states the reason for its exclusion |
| **R-5 No personal profiling** | Do not analyse author identity, name, nationality or organisation. Repository ownership is used only for ecosystem statistics, never to point at an individual |
| **R-6 Data minimisation** | The corpus index contains no personal contact details; the commit author field is discarded from any public dataset |
| **R-7 Coordinated disclosure** | After finding a malicious sample, **notify the registry privately first** (ClawHub / skills.sh), allow a 7-day response window, then publish. **This one is the lifeline of our credibility** |
| **R-8 Honeypot risk** | Never wire the scanner into any automation that executes things; the GitHub Action is read-only and writes only SARIF |

### 3.2 The coordinated disclosure flow (R-7 in detail)

```
Find a malicious sample
  ├─ ① Open an internal ticket recording the digest + rule IDs (not the payload)
  ├─ ② Notify the registry maintainers (skills.sh / ClawHub) with the digest and rules
  ├─ ③ Wait out the 7-day response window
  ├─ ④ If they do not act  → cite it in the report by digest, still without publishing the payload
  └─ ⑤ If they do act      → record it in the report as "coordinated removal", which is a positive story in itself
```

**A bonus**: this step is very likely to bring a collaboration with the registry
(offering them scanning capability), which is a longer-lived asset than publicity.

### 3.3 The tool's own compliance

- Prefer the GitHub REST API plus the tarball endpoint; **do not `git clone` whole
  repositories** (lower bandwidth and storage)
- The local cache is encrypted and size-capped; after collection the raw payloads are
  purged per policy, keeping only digests
- The scanner runs in a restricted container / as a low-privilege user (a second line of
  defence: even though it is designed not to execute, the possibility is still bounded)

---

## 4. Metric definitions (precise, to avoid ambiguity)

Every metric must state: the numerator, the denominator, what the denominator includes,
and what it excludes.

### 4.1 The primary metric

```text
Prevalence(R) = |{ skill ∈ corpus : skill has ≥1 finding matching rule R }| / |corpus|
```

**Denominator**: `corpus` = every skill that passed deduplication and the validity checks.
**Exclusion**: a skill whose parse failed and whose frontmatter could not be extracted
must be reported separately (it must never be silently dropped, see §6.3).

### 4.2 Mandatory stratification

Every `Prevalence(R)` must also be reported broken down by: source layer · size bucket ·
contains-scripts · install-count quantile (L1 only) · license status. Without that it
cannot be interpreted.

### 4.3 Precision/recall measurement (the core of credibility)

**Sampling**: randomly draw **500 skills** from each stratum (≈ 2,000 across strata) to
form the annotation set `GOLD`.

**Annotation process**:
1. Two annotators label independently (for a single-person project → at least one
   external volunteer plus one reviewer)
2. Record **agreement**: Cohen's κ, target ≥ 0.75; below that, fix the rule definition
   first and re-annotate
3. Disagreements are adjudicated by a third party, and the adjudication is recorded in
   the dataset
4. **Annotators must not see the rule's output details** (to avoid anchoring bias) → a
   `skillguard inspect --no-rules` mode that gives only the normalized text and line
   numbers

**Metrics**:
```text
Precision(R) = TP / (TP + FP)      # the rule flagged it, a human judged it a false positive
Recall(R)    = TP / (TP + FN)      # a human judged it a problem, the rule did not flag it
```
- Report **per-rule** P/R; do not hide a bad rule behind a micro-average
- For low-precision rules, give a **concrete false-positive sample** analysis
- **No post-hoc tuning whatsoever** (it is not allowed to "look at the annotation set,
  change a rule, and report again"). If iteration is unavoidable, version the annotation
  set (`GOLD-v1`, `GOLD-v2`), and report every metric independently per version. That is
  the floor of research integrity

### 4.4 A cross-tool benchmark (strongly recommended: low cost, high value)

Run **at least 2 existing tools** over the same 1,000-item subsample of `GOLD`:

| Comparison target | Command | Purpose |
|---|---|---|
| SkillMD | `npx skillmds scan <path>` | The engine behind the largest registry |
| skill-preflight | `npx skill-preflight scan <path>` | The representative of the scoring approach |
| (optional) SkillSpector | Python | From NVIDIA; the static-checking approach |

**Output**: one table of `rule coverage × false-positive rate × runtime × offline or not`.

> That one table is the proof of the project's technical moat.
> Pay particular attention to verifying the "offline" column — it is the shared weakness
> of every existing commercial option.

**Note**: running competitor tools requires their latest stable version, compliance with
their ToS, and public corpus only; the report must state the version numbers and how they
were run (their output changes, so the results are not reproducible and that must be said).

---

## 5. Deliverables

| # | Artifact | Path | Description |
|---|---|---|---|
| D1 | Pre-registered research protocol | `research/PROTOCOL.md` | Hypotheses, sampling, metric definitions, **timestamp**. Committed before scanning, to prevent moving the goalposts later |
| D2 | ToS review record | `research/TERMS-REVIEW.md` | The ToS conclusion and compliance basis for each data source |
| D3 | Corpus manifest | `research/corpus-manifest.json` | Pinned commit + digest + stratum labels |
| D4 | Annotation set | `research/gold/` | `GOLD-v1` + the annotation guide + agreement statistics |
| D5 | Raw scan results | `research/raw-findings.jsonl` | One line per finding (with digest/rule/file/line) |
| D6 | Aggregated dataset | `datasets/skill-corpus-2026q4.jsonl(.zst)` | **Publicly releasable**, with redacted evidence |
| D7 | **The main report** | `docs/CORPUS_REPORT.md` | Conclusions, tables, stratified analysis, false-positive analysis, limitations |
| D8 | Cross-tool benchmark | `docs/BENCHMARK.md` | The comparison table against SkillMD / skill-preflight |
| D9 | arXiv preprint | — | A measurement of the ecosystem's security posture (an external researcher as second author raises credibility) |
| D10 | Technical blog post | — | A developer-readable version (HN material) |
| D11 | Coordinated disclosure record | `research/DISCLOSURE.md` | Timeline, who was notified, the outcome |

### 5.1 Honest statements the main report must contain (hard-coded into the template; do not delete)

```text
1. Detection is not judgement. This study does not judge any skill to be malicious; it
   reports reproducible rule matches only.
2. The rules have false negatives. The false-negative rate for semantic-level prompt
   injection is unknown and necessarily non-zero.
3. False positives exist. Every prevalence figure is bounded by the precision in §4.3;
   the interval for the true prevalence is [P × point estimate, point estimate].
4. The corpus is biased. GitHub code search is limited by the platform's indexing, the
   registries have their own preferences, and the conclusions do not necessarily
   generalise to private/enterprise skills.
5. The corpus drifts. Every conclusion is bound to a collection window and a commit and
   cannot be cited permanently.
```

---

## 6. Technical implementation (minimal additions)

Only a "batch driver" on top of the Phase 1 scanner is needed; no new subsystem.

### 6.1 New capabilities

```text
skillguard corpus fetch  --source <l1..l5> --limit N --out research/raw/
skillguard corpus scan   --manifest research/corpus-manifest.json --out research/raw-findings.jsonl
skillguard corpus stats  --findings <jsonl> --by layer,stratum --format markdown,json
skillguard corpus report --findings <jsonl> --gold research/gold/GOLD-v1 --out docs/
```

**Core requirements**:
- **Throughput**: the median scan time for 100k skills must be < 15 ms (including I/O) →
  roughly 25 minutes on one machine. Use rayon parallelism plus a content-dedup cache
- **Idempotence**: rerunning the same manifest produces a **byte-identical** jsonl
  (timestamps excepted)
- **No network**: `corpus scan` / `stats` / `report` are entirely offline and read only
  the local manifest
- **Degradation**: a skill that fails to parse or times out must be recorded and then
  skipped, never aborting the batch (the most common fragility in batch tools)

### 6.2 Measurement cache

Scan results are cached globally by digest (SQLite, or a `content_digest → findings`
map), so rescanning (a rerun, the cross-tool benchmark) costs nothing. This is the
precondition that makes the §4.4 benchmark practical.

### 6.3 Failure must be visible

```text
total      = 100,000
scanned    =  99,847
failed     =    153     ← a dedicated subsection must explain the distribution of failure reasons
skipped    =      0
binary     =     12
oversize   =     41
```
It is **forbidden** to silently fold `failed` into the denominator or to drop it. This is
the most easily attacked point of any batch study.

---

## 7. Time and cost estimate

| Step | Duration | Cost |
|---|---|---|
| Protocol + ToS review + coordinated disclosure process | 3–5 days | 0 |
| The Phase 1 scanner (prerequisite) | 2–3 weeks | 0 |
| Corpus collection (under rate limits) | 2–4 days | 0 (the GitHub free tier suffices) |
| Building the annotation set (including κ statistics) | 2 weeks | 0–a little (volunteers / one paid external annotator) |
| Cross-tool benchmark | 3 days | 0 |
| Main report + blog + preprint | 1 week | 0 |
| **Total (excluding Phase 1)** | **≈ 6 weeks** | **≈ 0** |

**Storage estimate**: 100k skills × a 15 KB median ≈ 1.5 GB of raw content, ≈ 0.8 GB after
deduplication, ~300 MB compressed. Entirely affordable on a personal machine.

**The only real cost is attention**: about 6 weeks × 10 hours a week ≈ 60 hours. That is
the **only hard gate** for deciding whether to continue (compare the maintainer-effort cap
in MVP.md §7).

---

## 8. Execution order (every gate can stop the project)

```
G0  Protocol + ToS review passed?              ──► no → choose different sources, or drop some
G1  Phase 1 scanner all green + throughput met? ──► no → back to Phase 1, no research yet
G2  Coordinated disclosure process set up (with registry contacts)? ── no → resolve before collecting
G3  GOLD-v1 κ ≥ 0.75?                          ──► no → fix the rule definitions, re-annotate
G4  Precision ≥ 0.85 and Recall ≥ 0.6?         ──► no → iterate to GOLD-v2, report both versions
G5  Have the registries been notified?          ── no → do not publish the report
G6  Report published and dataset public?       ──► move on to productising Phase 1
```

**G4 is the critical one**: if precision falls short, do **not** loosen the definition to
make the number, but **report the low precision honestly** and bound the conclusion as an
upper estimate. An honest "our precision is only 0.62" is worth far more than a padded 0.95.

---

## 9. Known limitations (pre-registered, so no excuses are invented later)

1. GitHub code search only indexes files that meet the platform's conditions → the corpus
   is a lower bound
2. Skills on public registries have already been partly reviewed, so their distribution
   differs from "long-tail private skills"
3. ClawHub is known to have been poisoned, so its prevalence **cannot** be extrapolated to
   other registries (it must be reported separately)
4. Static analysis cannot do anything about semantic-level injection (false negatives
   unknown)
5. A single-window snapshot does not reflect change over time
6. The annotators are us or people we know, so there is a positional bias → κ and external
   annotators mitigate it but cannot remove it

---

## 10. How it feeds later phases

```
Phase 0 output ─┬─→ stratified prevalence + false-positive analysis ──→ feeds back into rule design and severity calibration
                ├─→ the GOLD-v1 annotation set ──────────────────────→ becomes the project's permanent regression baseline
                ├─→ a public dataset ────────────────────────────────→ a long-term backlink for academic citation
                ├─→ the cross-tool table ────────────────────────────→ the README's technical moat
                └─→ contacts with registries ────────────────────────→ an entry point for long-term collaboration

Phase 1 input: GOLD-v1 is a ready-made real regression suite (far better than self-made fixtures)
```

> **An underrated benefit**: `GOLD-v1` will become one of the project's most valuable
> assets. Semgrep's 3,000+ community rules grew exactly this way — we do not have a
> community's scale, but we can start with 2,000 **real, human-annotated, public**
> labelled samples.
