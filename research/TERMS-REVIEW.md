# Terms of Service Review

**Reviewed**: 2026-10-07, before any collection.
**Method**: read each source's published terms, robots.txt and API documentation.
**Outcome vocabulary**: `permitted` / `restricted` / `forbidden` / `unclear`.

This review is the G0 gate for [PROTOCOL.md](PROTOCOL.md) §3. A source whose
terms forbid automated collection is excluded from the corpus, and the exclusion
is reported in the findings rather than quietly dropped.

> **This is an engineering assessment, not legal advice.** It is recorded so the
> decision is auditable and so a maintainer with actual expertise can overturn
> it. Where the answer is `unclear`, the default is to contact the operator
> first and wait, not to proceed and hope.

---

## L3 · GitHub code search — `permitted` with conditions

**Basis**: GitHub REST API documentation; `robots.txt`; the API Terms of Service.

| Condition | Detail |
|---|---|
| Authentication | Personal access token required. Anonymous search is throttled far harder. |
| Rate limit | 5,000 requests/hour authenticated. We cap at **1 req/s** with exponential backoff and a 429 circuit breaker, i.e. ~10× under the ceiling. |
| Content storage | Response bodies are cached locally during collection and purged after digest extraction. Only `path`, `repo`, `commit`, `content_digest` are retained. |
| Deletion | On request from a repository owner, the corresponding manifest entries are removed and the study re-runs. |
| Attribution | Repo path and commit are recorded. No personal identity data. |

robots.txt for github.com does not disallow the API paths used.

**Decision: permitted.**

---

## L1 · skills.sh — `unclear`, contact first

**Basis**: public leaderboard and skill pages; MIT-licensed registry code; no
published terms for automated enumeration.

- The site is explicitly a public-good, open index, and its skill pages are
  already fetchable.
- No stated API for bulk enumeration, and no stated policy either way.
- Absence of a prohibition is **not** permission.

**Decision: `unclear` → excluded from the automated corpus until the operator
responds.** Contact drafted at `research/DISCLOSURE.md` §2 before any fetch.
If they decline, L1 is replaced by L4/L5 and install-count stratification is
dropped (which weakens H6/H7 slightly, since a registry's most-installed skills
are the most interesting ones — that limitation will be reported).

---

## L2 · ClawHub — `unclear`, coordinate first

**Basis**: public listing; prior independent security audits published on the
record (Koi Security, Feb 2026).

- ClawHub is a known-poisoned marketplace. Scanning it is both the most
  security-relevant layer **and** the one where our findings could cause visible
  takedowns.
- That raises the stakes in both directions: we must not disrupt a maintainer's
  moderation process, and we must not sit on live malicious samples.

**Decision: `unclear` → excluded from automated collection until contact is
made and a disclosure channel agreed.** The disclosure protocol
([PROTOCOL.md](PROTOCOL.md) §8) applies with priority to this layer: samples
found here are reported privately first, and we do not publish a ClawHub
prevalence figure without that having happened first.

**Note on reuse**: Koi Security's and Unit 42's published counts are used as
*external comparison*, clearly attributed, and never merged into our corpus.

---

## L4 · skillmd.com — `restricted`

**Basis**: the project publishes a documented, public, unauthenticated JSON API
and an `llms.txt` index, and states that the local CLI sends nothing anywhere.

- A public API is published for consumption, so querying it is intended use.
- However, a full-corpus enumeration at research volume is a heavier pattern
  than the API was offered for, and the registry has no opt-out or
  rate-limit-under-load commitment we can rely on.
- Its own security page shows it deliberately caps third-party scanner coverage
  (4.5% of listed skills carry an independent scan result) — it is protective of
  its corpus.

**Decision: `restricted` → not used for bulk enumeration.** The documented
per-skill endpoint may be used at low volume to cross-check H1–H10 on a small
sample, attributed, without bulk crawling. If skillmds offers a research
endpoint or bulk access, revisit.

---

## L5 · skillsmp.com — `unclear`, contact first

**Basis**: public listing pages, no published terms or API.

**Decision: `unclear` → excluded pending contact**, same handling as L1.

---

## Net effect on the study

With the current decisions, the **only source cleared for bulk automated
collection is L3 (GitHub code search)**.

That is enough to proceed, with consequences we accept up front:

| Effect | Handling |
|---|---|
| No registry layer, so no install-count stratification | Report H1–H5 and H8–H10 without install-count cuts; treat "popularity vs risk" as unaddressed. |
| ClawHub prevalence cannot be stated by us | Cite Koi Security / Unit 42 figures with attribution as external comparison. |
| GitHub-only corpus may under-represent polished registry skills | State plainly that the corpus is a lower bound and likely skewed toward independently-authored skills. |
| Skills copied across repos are deduped by digest, so "how widely is a risky skill copied" becomes measurable — arguably a better story than a registry count | Report the copy-multiplicity distribution as a first-class finding. |

None of these weaken H6 (almost nobody declares permissions). If anything, a
GitHub-sourced corpus strengthens it: it is where skills are copied and never
reviewed.

**G0 gate: PASSED** with the scope above.
