# Corpus Study Protocol (pre-registration)

**Status**: pre-registered before any data collection.
**Frozen at**: this file is committed to `main` before the first fetch. Any change
afterwards is a new version (`PROTOCOL-v2.md`) and the earlier version's numbers
stay in the report.

This document exists so the study cannot be quietly reshaped after the results
are known. In security research, the most common way a corpus study becomes
worthless is not that the data was bad — it is that the denominator moved.

> **Tooling status (2026-10-07, non-normative).** The protocol above is
> unchanged; this note only records what the scanner can now do.
> `skillguard corpus index|scan|stats|report|reproduce` implement §6 offline:
> `index` turns a local checkout into a manifest pinned to full commits and
> `sgdir-v1` digests, `scan` is cached by digest and produces byte-identical
> JSONL across runs, and the denominators table lists every failed entry rather
> than hiding it. Network collection is still blocked on
> [DISCLOSURE.md](DISCLOSURE.md) §3 (issue #5). `skillguard inspect --labeling`
> is the rules-free view §7 requires for the GOLD set.
> See `tests/corpus.rs` for the reproducibility tests.

---

## 1. Hypotheses

| ID | Hypothesis | Metric |
|---|---|---|
| H1 | Hardcoded credentials are present in the public skill corpus at a measurable rate | `Prevalence(SECRET_*)` |
| H2 | Download-to-execute chains exist in the wild | `Prevalence(DL_CHAIN_FETCH_EXECUTE)` |
| H3 | Shell execution and privilege escalation are common | `Prevalence(SHELL_*)` |
| H4 | Sensitive-path and environment access are common | `Prevalence(SECRET_PATH_READ, SECRET_ENV_DUMP)` |
| H5 | Deterministic prompt-injection heuristics have a high hit rate | `Prevalence(PI_*)` |
| H6 | **Almost no skill declares its permissions** | `Prevalence(declared_permissions)` |
| H7 | **Among skills that do declare, a material fraction under-declare** | `under_declared_rate` |
| H8 | Obfuscation is used in practice, not just theorised | `Prevalence(OBFUSC_*)` |
| H9 | Dependencies are frequently unpinned or typosquatted | `Prevalence(DEP_*)` |
| H10 | License declarations are frequently absent or contradictory | `Prevalence(LICENSE_*)` |

H6 and H7 are the ones that matter. They size the gap this project exists to
close, and they are the numbers a prospective user can act on.

**Null for H6**: ≥ 20% of sampled skills declare permissions.
If that holds, the declared-vs-observed product has no market and Phase 2 is
cancelled rather than re-scoped.

---

## 2. Definitions (frozen)

```text
corpus          = the set of unique skills passing all validity checks in §4
Prevalence(R)   = |{ s ∈ corpus : s has ≥1 finding of rule R }| / |corpus|
```

Every prevalence is reported with its **stratified breakdown** (§5) and its
**precision** (§7). A prevalence without a precision is not a result.

Explicitly **not** claimed:

- That a skill matching a rule is malicious. We report evidence, not verdicts.
- That a skill not matching a rule is safe. Static analysis of natural-language
  instructions has non-zero and unmeasured miss rate.
- That the corpus represents private or enterprise-internal skills. It does not.

---

## 3. Data sources

| Layer | Source | Access | Status |
|---|---|---|---|
| L1 | skills.sh public index | public listing pages | pending ToS review |
| L2 | ClawHub | public listing | pending ToS review |
| L3 | GitHub code search `filename:SKILL.md` | REST API, authenticated | permitted under GitHub ToS |
| L4 | skillmd.com public API | public, unauthenticated | pending ToS review |
| L5 | skillsmp.com | public listing | pending ToS review |

See `TERMS-REVIEW.md` for the per-source decision. **A source whose terms forbid
automated collection is excluded, and the exclusion is reported** rather than
quietly dropped.

Target: N = 100,000 unique skills after content-level deduplication.

---

## 4. Validity checks

A sampled artifact enters `corpus` only if all hold:

1. It contains a readable `SKILL.md` at its root.
2. Its content is valid UTF-8 (or is skipped with a recorded reason).
3. Its `content_digest` (sgdir-v1) is not already in `corpus` — deduplication is
   by content, not by path, because ~50% of skills are byte-identical copies.
4. Its `commit` is a **full 40-hex SHA**. Tags, branches and short SHAs are
   rejected: they are not reproducible, and a corpus pinned to a moving ref is
   not a result.

Failures are counted per-check and reported. `failed` is never folded into the
denominator silently.

---

## 5. Stratification

Sampling is stratified on six axes so the headline number is not dominated by
one category (69.7% of listed skills are categorised `AI Tool`):

| Axis | Strata |
|---|---|
| source | L1 / L2 / L3 / L4 / L5 |
| size | <8 KB / 8–32 KB / 32–128 KB / >128 KB |
| scripts | none / shell / python / js-ts / other |
| declared permissions | present / absent |
| license | LICENSE file present / absent / declared-and-conflicting |
| install count (L1 only) | top 1% / 1–10 / 10–50 / 50–100 / tail |

Every reported prevalence carries its per-stratum `n`. Oversized layers use
**systematic sampling** (repository id mod k) rather than simple random, so the
selection is reproducible from the manifest alone.

---

## 6. Reproducibility

Each analysed skill is recorded as:

```json
{ "source_id": "...", "commit": "<40-hex>", "content_digest": "sha256:...",
  "layer": "L1", "strata": {...}, "rule_set_version": "0.1.0",
  "collected_at": "<RFC3339 UTC>" }
```

- `corpus-manifest.json` is committed under `research/`.
- `skillguard corpus reproduce <manifest>` re-runs the analysis offline.
- All numbers bind to a collection window and to `rule_set_version`. Bumping the
  rule set invalidates comparison; the report states which version produced it.

---

## 7. Precision and recall

Ground truth: **stratified sample of 500 skills per stratum** (~2,000 total),
drawn at random and labelled by hand.

- Two independent labelers, blind to rule output (`skillguard inspect` shows
  normalized text and line numbers only).
- **Cohen's κ ≥ 0.75 required.** Below that, the rule definitions are defective
  and labelling restarts after fixing them.
- Disagreements adjudicated by a third party; the adjudication is recorded in
  the dataset.
- `Precision(R)` and `Recall(R)` reported **per rule**, never micro-averaged,
  because a micro-average hides the bad rules.

**No post-hoc tuning.** The label set is versioned (`GOLD-v1`, `GOLD-v2`); each
version reports all metrics independently. Looking at labels, changing rules and
re-reporting the same version is prohibited — that is how precision numbers stop
meaning anything.

**Gate G4**: `Precision ≥ 0.85` and `Recall ≥ 0.60` overall.
If G4 fails, we publish the measured precision as an **upper bound on true
prevalence** and say so. A published 0.62 is worth more than an unpublished 0.95.

The end-to-end procedure — the draw, the two blind worksheets, the
`corpus agreement` command that computes Cohen's κ, and the freeze rule — is in
[`research/GOLD.md`](GOLD.md).

---

## 8. Disclosure protocol

| Step | Action | Timing |
|---|---|---|
| 1 | Record digest + rule internally; never store payload content | on detection |
| 2 | Notify the registry maintainer with digest and rule id | within 24 h |
| 3 | Wait for response | 7 days |
| 4 | If unresolved, publish referencing the digest only | day 8+ |
| 5 | If resolved, record as "coordinated removal" | in report |

**Payload content is never published**, in any artefact, including the dataset.
A malware corpus is a distribution mechanism; the study needs digests, not code.

**Gate G5**: no public report before step 2 is complete for every sample.

---

## 9. Anti-abuse constraints

| Constraint | Enforcement |
|---|---|
| Never execute or install scanned content | scanner has no `Command`/network path; enforced by module boundary and `forbid(unsafe_code)` |
| Never upload skill content anywhere | offline analysis only; findings stay local |
| Rate-limit all collection | self-imposed ceiling below platform limits, exponential backoff on 429 |
| Do not analyse personal identity | no author profiling; `commit` author metadata discarded in the public dataset |
| Minimise raw payload retention | raw bytes cached locally, purged after analysis, digest retained |
| Do not publish payloads | §8 |

---

## 10. Known limitations (declared in advance)

1. GitHub code search indexes only files meeting platform conditions → the
   corpus is a **lower bound**.
2. Public-registry skills have already been partially reviewed; their
   distribution differs from long-tail private skills.
3. ClawHub is known to be poisoned. Its prevalence **must not** be extrapolated
   to other layers — reported separately, always.
4. Semantic prompt injection is out of reach of static analysis. Miss rate is
   unknown and non-zero.
5. Single time window. Nothing here describes how the ecosystem evolves.
6. Labellers are the authors and their colleagues: bias is mitigated by κ and an
   external labeller, not eliminated.

---

## 11. Gates

| Gate | Condition | On failure |
|---|---|---|
| G0 | Protocol committed; ToS review done per source | re-scope or drop the source |
| G1 | Scanner green, throughput ≥ 6,600 skills/min | fix the scanner; do not collect |
| G2 | Disclosure process established with named contacts | resolve before collecting |
| G3 | GOLD-v1 κ ≥ 0.75 | fix rule definitions, relabel |
| G4 | Precision ≥ 0.85, recall ≥ 0.60 | iterate to GOLD-v2; publish upper bound if still short |
| G5 | All samples disclosed to registries | do not publish |
| G6 | Report and dataset published | proceed to Phase 1 productisation |

H6's null (§1) is evaluated after G3: if ≥20% of the corpus declares
permissions, Phase 2 is cancelled and the project narrows to Phase 1 as a
scanner.
