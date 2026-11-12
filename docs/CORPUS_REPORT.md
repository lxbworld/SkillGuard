# SkillGuard Phase 0 corpus report

> **This is a pilot, not the pre-registered study.** The sample is an
> opportunistic GitHub code-search slice, not the stratified N=100,000 draw in
> `research/PROTOCOL.md` §5, and the precision column comes from model
> annotators rather than the two humans `research/PROTOCOL.md` G3 asks for. Read
> the numbers as a first signal and a proof that the pipeline runs on real data,
> not as the study's result.
>
> The `LICENSE_MISSING` figure is corrected for repository-root licenses: a
> skill vendored in a repository inherits that repository's license, and the
> corpus tree is not a git checkout, so the collector records the repo-root
> license and `corpus scan` honours it. Before the correction this rule read
> 87.2%; on a 30-skill sample, 19 of 30 flagged skills (63%) had a repo-root
> LICENSE. A second error was attribution: GitHub search surfaces one
> `SKILL.md` per hit, but the walker finds every nested `SKILL.md` in the
> fetched tree, and nested skills had no provenance row — they were credited to
> whatever repository enclosed the tree (SkillGuard) and lost their own
> repository's license. The join now matches provenance by repository, so all
> every row carries its true repository and repository-root license.
>
> A precision pass over the first real corpus also corrected several heuristics
> that fired on ordinary text and file formats: lookalike characters in
> legitimate non-Latin prose, npm/pip/cargo integrity hashes, shields.io badges,
> the word "silently" in documentation, `regex.exec(`, file extensions that look
> like TLDs (`.zip`, `.mov`), XML namespaces, English-only keyword lists that
> flagged every non-English `PI_DESCRIPTION_MISMATCH`, and unstemmed verbs
> (`execution` did not match `execute`). Each fix is a regression test.
>
> ## GOLD-v10
>
> The precision column below is measured against `research/gold/GOLD-v10.jsonl`:
> 205 line-level findings across 36 rules at `SCAN_LOGIC_REVISION = 53`, eight
> per rule in hash order, one judgment per skill and rule. Two annotators from
> **different model families** labelled them blind to each other —
> `command-code/deepseek-v4.1-flash` and `command-code/z-ai/glm-5.3-flash` —
> **no human annotated this set**, and neither annotator wrote the rules.
> Cohen's kappa is **0.779** over the 205 rows (gate 0.75); the 20 disagreements
> were adjudicated by a third session shown both verdicts, and every rule figure
> below is per rule, never micro-averaged.
>
> This round exists because two sessions of *one* model is not independence: they
> share blind spots and agree on a wrong label as readily as a right one.
> GOLD-v8 measured that directly by re-labelling GOLD-v6's unchanged 209 rows
> with a second family — kappa fell from 0.845 to **0.723**, below the gate. The
> 0.779 here is what two families reach once the ambiguity that split them is
> removed, and *that* was a defect in this project's own annotation instruction,
> not in the rules: it said documentation is not an instance without saying what
> a `SKILL.md` body is. The body is the instruction an agent follows, so a
> command in it is behaviour; only a passage that talks *about* a command
> (`never run curl | bash`) is a mention. One round (GOLD-v9) failed at 0.593
> before that sentence was added, and its labels are kept as the record.
>
> The frontmatter parser changed at revision 50 (`serde_yaml`, deprecated, and
> the unmaintained `unsafe-libyaml` behind it, replaced by `serde-saphyr` — issue
> #16). The cost is measured and stated: `PARSE_FAILED` goes 71 -> 76 on the same
> corpus. Four of the five are real skills whose frontmatter is valid to libyaml
> and PyYAML but not to the YAML 1.2.2 grammar — a quoted scalar continued at the
> key's own column — and the fifth (`name: {{SKILL_NAME}}`) is not valid YAML at
> all. The declaration rate is unaffected (386 skills declare, before and after),
> and everything else is identical.
>
> The label set was drawn at revision 50. Revision 51 changed **capability
> derivation only** — shell variables, regex character classes and attribute
> accesses are no longer recorded as file paths — which altered no text rule and
> therefore no row above; it did remove four false `MISMATCH_UNDER_DECLARED`
> accusations from the prevalence table.
>
> **Revision 53 is a line-kind model (T14), and it removes findings rather
> than adding them.** A docstring or block comment describes behaviour; it does
> not perform it, and a single-line comment check cannot see the `"""` that
> opened forty lines earlier. `SHELL_EXEC` drops 2,495 -> 1,646 (that rule alone
> is most of the 9,853 -> 8,776 total), `NET_DOMAIN_LITERAL` 2,888 -> 2,768,
> `FS_HOME_ACCESS` 289 -> 235. On GOLD-v6 it suppressed 7 rows and
> **all seven were false positives**, which is why the change was made: the same
> two model families independently rated findings on docstring lines 7% and 14%
> true against 72% and 73% on executable code. Markdown is deliberately *not*
> documentation here — a fenced `pip install` is the command the agent is told to
> run (GOLD-v8 confirms it, 48% precision, and the `remote-install` fixture
> requires it) — so `PI_*` and `DL_*` behaviour is unchanged in `SKILL.md`.
>
> Neither annotator being human is the limitation, not a detail. Two sessions of
> one model share blind spots, so they agree on a wrong label as readily as on a
> right one, and the kappa above is a test–retest figure rather than inter-human
> agreement. `research/GOLD.md` says what that costs and what would fix it.
>
> **13 of 36 rules reach the 0.85 precision gate**, and ten of them are at 100%:
> `FS_PATH_ESCAPE`, `NET_HTTP_CLIENT`, `FS_SENSITIVE_PATH`, `FS_MODE_UNRESOLVED`,
> `NET_DYNAMIC_URL`, `LICENSE_RESTRICTIVE`, `FS_HOME_ACCESS`,
> `SECRET_PROVIDER_TOKEN`, `DL_CHAIN_FETCH_EXECUTE` and `DEP_UNPINNED_SCRIPT`.
> `FS_RECURSIVE_WALK`, `NET_FETCH_CALL` and `SECRET_ENV_DUMP` are at 7/8.
> (GOLD-v5 measured `FS_PATH_ESCAPE` and `NET_HTTP_CLIENT` at 87.5%.)
>
> Where they did not: `SHELL_PRIVILEGE_ESCALATION` 0/8, `PERSIST_HOOK` 0/6,
> `PERSIST_SHELL_RC` 0/4, `PI_INJECTION_OVERRIDE` 0/8 and `DL_PIPE_TO_SHELL` 0/2
> were false positives on every sampled finding. The `PI_*` family is where
> GOLD-v5 left it — the corpus is full of security *training* material that
> discusses injection, and a phrase rule cannot tell "issues this" from
> "documents this", which is why they are `Info`: a false `Critical` is worse
> than no finding. They still force a human to read the line; they no longer
> block a gate. Treat every prevalence figure below as an upper bound.
>
> Two **skill-level** rules are excluded rather than measured: `PARSE_FAILED` and
> `PI_DESCRIPTION_MISMATCH` report on the skill as a whole and carry no evidence
> line, so a line-level judgment about them is a judgment about the frontmatter
> delimiter. GOLD-v5 sampled them anyway and published a 0% that measured the
> sampling, not the rule; `research/build_gold.py` now refuses to sample them.
> They need a skill-level questionnaire like `SKILL-v1` below.
>
> (GOLD-v1..v5 stay in `research/gold/`. Versions are not directly comparable:
> both the raters and the rule set change.)
>
> A separate **skill-level** pass (`SKILL-v1`, 30 skills, questionnaire, no rule
> output) measured `PI_DESCRIPTION_MISMATCH` directly: precision **17.6% / 35.3%**,
> and the underlying "is the description understated?" judgment has **κ 0.359** —
> the annotators cannot agree on it. Breaking it down by branch: the **network
> and shell branches scored 0/6 correct**, the credential branch 1-2/4. The two
> dead branches have been **removed**; what remains is the checkable case (the
> code reads credentials and the description mentions neither credentials nor
> security). Prevalence fell 10.7% -> 6.4%. See `research/GOLD.md`.
>
> The `PI_*` heuristics that remain are measured above, and every one of them is
> below the gate. They are published because the evidence line is still worth a
> human read, and their prevalence figures are upper bounds like every other row.





## Collection

```json
{
  "queries": [
    "filename:SKILL.md",
    "filename:SKILL.md path:skills",
    "filename:SKILL.md path:skills/",
    "filename:SKILL.md path:.claude",
    "filename:SKILL.md path:.claude/skills",
    "filename:SKILL.md path:agent",
    "filename:SKILL.md path:agent/skills",
    "filename:SKILL.md path:agents",
    "filename:SKILL.md path:agents/skills",
    "filename:SKILL.md path:.cursor",
    "filename:SKILL.md path:.cursor/skills",
    "filename:SKILL.md path:plugins",
    "filename:SKILL.md path:commands",
    "filename:SKILL.md path:.github",
    "filename:SKILL.md path:.github/skills",
    "filename:SKILL.md path:templates",
    "filename:SKILL.md path:.codex",
    "filename:SKILL.md path:.gemini",
    "filename:SKILL.md path:.agent",
    "filename:SKILL.md path:.agents",
    "filename:SKILL.md path:.windsurf",
    "filename:SKILL.md path:.trae",
    "filename:SKILL.md path:.roo",
    "filename:SKILL.md path:.continue",
    "filename:SKILL.md path:prompts",
    "filename:SKILL.md path:workflows",
    "filename:SKILL.md path:mcp",
    "filename:SKILL.md path:tools",
    "filename:SKILL.md path:functions",
    "filename:SKILL.md path:recipes",
    "filename:SKILL.md path:playbooks",
    "filename:SKILL.md path:assistants",
    "filename:SKILL.md path:modes",
    "filename:SKILL.md path:rules",
    "filename:SKILL.md path:capabilities",
    "filename:SKILL.md path:packages",
    "filename:SKILL.md path:integrations",
    "filename:SKILL.md path:automation",
    "filename:SKILL.md path:examples",
    "filename:SKILL.md path:docs",
    "filename:SKILL.md path:src",
    "filename:SKILL.md path:lib",
    "filename:SKILL.md path:apps",
    "filename:SKILL.md path:services",
    "filename:SKILL.md path:backend",
    "filename:SKILL.md path:frontend",
    "filename:SKILL.md path:infra",
    "filename:SKILL.md path:ops",
    "filename:SKILL.md path:security",
    "filename:SKILL.md path:data",
    "filename:SKILL.md path:ai",
    "filename:SKILL.md path:llm",
    "filename:SKILL.md path:copilot",
    "filename:SKILL.md path:claude",
    "filename:SKILL.md path:openai",
    "filename:SKILL.md path:anthropic"
  ],
  "per_query_counts": {
    "filename:SKILL.md": 100,
    "filename:SKILL.md path:skills": 100,
    "filename:SKILL.md path:skills/": 100,
    "filename:SKILL.md path:.claude": 100,
    "filename:SKILL.md path:.claude/skills": 100,
    "filename:SKILL.md path:agent": 100,
    "filename:SKILL.md path:agent/skills": 100,
    "filename:SKILL.md path:agents": 100,
    "filename:SKILL.md path:agents/skills": 100,
    "filename:SKILL.md path:.cursor": 100,
    "filename:SKILL.md path:.cursor/skills": 100,
    "filename:SKILL.md path:plugins": 100,
    "filename:SKILL.md path:commands": 100,
    "filename:SKILL.md path:.github": 100,
    "filename:SKILL.md path:.github/skills": 100,
    "filename:SKILL.md path:templates": 100,
    "filename:SKILL.md path:.codex": 100,
    "filename:SKILL.md path:.gemini": 100,
    "filename:SKILL.md path:.agent": 100,
    "filename:SKILL.md path:.agents": 100,
    "filename:SKILL.md path:.windsurf": 100,
    "filename:SKILL.md path:.trae": 100,
    "filename:SKILL.md path:.roo": 100,
    "filename:SKILL.md path:.continue": 100,
    "filename:SKILL.md path:prompts": 100,
    "filename:SKILL.md path:workflows": 100,
    "filename:SKILL.md path:mcp": 100,
    "filename:SKILL.md path:tools": 100,
    "filename:SKILL.md path:functions": 94,
    "filename:SKILL.md path:recipes": 100,
    "filename:SKILL.md path:playbooks": 100,
    "filename:SKILL.md path:assistants": 77,
    "filename:SKILL.md path:modes": 100,
    "filename:SKILL.md path:rules": 100,
    "filename:SKILL.md path:capabilities": 100,
    "filename:SKILL.md path:packages": 100,
    "filename:SKILL.md path:integrations": 100,
    "filename:SKILL.md path:automation": 100,
    "filename:SKILL.md path:examples": 100,
    "filename:SKILL.md path:docs": 100,
    "filename:SKILL.md path:src": 100,
    "filename:SKILL.md path:lib": 100,
    "filename:SKILL.md path:apps": 100,
    "filename:SKILL.md path:services": 100,
    "filename:SKILL.md path:backend": 100,
    "filename:SKILL.md path:frontend": 100,
    "filename:SKILL.md path:infra": 100,
    "filename:SKILL.md path:ops": 100,
    "filename:SKILL.md path:security": 100,
    "filename:SKILL.md path:data": 100,
    "filename:SKILL.md path:ai": 100,
    "filename:SKILL.md path:llm": 100,
    "filename:SKILL.md path:copilot": 100,
    "filename:SKILL.md path:claude": 100,
    "filename:SKILL.md path:openai": 100,
    "filename:SKILL.md path:anthropic": 100
  },
  "unique_candidates": 5118,
  "sample": 5118,
  "candidates": 5118,
  "collected": 5124,
  "collected_this_run": 2608,
  "skipped": 141,
  "failed": 460,
  "api_calls": 2494,
  "collected_at_utc": "2026-10-08T08:03:26Z"
}
```

Rule set version: `0.1.2`.

This file is generated by `skillguard corpus report` from a findings JSONL. A number is only citable together with the manifest and the collection window it came from.

## Honest declarations

- Detection is not judgement. This study does not classify any skill as malicious; it reports reproducible rule matches.
- Rules miss things. The miss rate for semantic prompt injection is unknown and necessarily non-zero.
- False positives exist. Every prevalence figure is bounded by the precision in the GOLD set; the interval for true prevalence is [P x point estimate, point estimate].
- The corpus is biased. GitHub code search is limited by the platform's index and every registry has its own preference; the conclusions do not necessarily generalise to private or enterprise skills.
- The corpus drifts. Every conclusion is bound to the collection window and the pinned commits and cannot be cited forever.

## Denominators

| | count |
|---|---|
| manifest entries | 5442 |
| scanned | 5442 |
| failed | 0 |

## Overall prevalence

Prevalence(R) = skills with at least one finding for R / scanned skills.

| rule | hits | n | prevalence |
|---|---|---|---|
| `LICENSE_MISSING` | 1148 | 5442 | 21.1% |
| `NET_DOMAIN_LITERAL` | 363 | 5442 | 6.7% |
| `SHELL_EXEC` | 343 | 5442 | 6.3% |
| `PI_DESCRIPTION_MISMATCH` | 212 | 5442 | 3.9% |
| `NET_FETCH_CALL` | 163 | 5442 | 3.0% |
| `FS_PATH_ESCAPE` | 138 | 5442 | 2.5% |
| `FS_RECURSIVE_WALK` | 133 | 5442 | 2.4% |
| `FS_HOME_ACCESS` | 104 | 5442 | 1.9% |
| `FS_ABSOLUTE_PATH` | 77 | 5442 | 1.4% |
| `MISMATCH_UNDER_DECLARED` | 76 | 5442 | 1.4% |
| `PARSE_FAILED` | 76 | 5442 | 1.4% |
| `NET_HTTP_CLIENT` | 53 | 5442 | 1.0% |
| `LICENSE_RESTRICTIVE` | 52 | 5442 | 1.0% |
| `OBFUSC_TRACKING_PIXEL` | 33 | 5442 | 0.6% |
| `PI_CONCEALMENT` | 29 | 5442 | 0.5% |
| `NET_DYNAMIC_URL` | 24 | 5442 | 0.4% |
| `MISMATCH_OVER_DECLARED` | 22 | 5442 | 0.4% |
| `SECRET_PATH_READ` | 15 | 5442 | 0.3% |
| `SHELL_PRIVILEGE_ESCALATION` | 14 | 5442 | 0.3% |
| `SHELL_EVAL` | 12 | 5442 | 0.2% |
| `PERSIST_AGENT_CONFIG` | 10 | 5442 | 0.2% |
| `PI_INJECTION_OVERRIDE` | 10 | 5442 | 0.2% |
| `SECRET_ENV_DUMP` | 10 | 5442 | 0.2% |
| `PI_EXFIL_INSTRUCTION` | 7 | 5442 | 0.1% |
| `DEP_CUSTOM_REGISTRY` | 6 | 5442 | 0.1% |
| `DL_UNTRUSTED_DOMAIN` | 6 | 5442 | 0.1% |
| `PI_SYSTEM_IMPERSONATION` | 6 | 5442 | 0.1% |
| `DL_REMOTE_INSTALL` | 4 | 5442 | 0.1% |
| `FS_SENSITIVE_PATH` | 4 | 5442 | 0.1% |
| `PERSIST_SHELL_RC` | 4 | 5442 | 0.1% |
| `SECRET_GENERIC_ASSIGN` | 4 | 5442 | 0.1% |
| `DEP_UNPINNED_SCRIPT` | 3 | 5442 | 0.1% |
| `FS_MODE_UNRESOLVED` | 3 | 5442 | 0.1% |
| `PERSIST_HOOK` | 3 | 5442 | 0.1% |
| `SECRET_PROVIDER_TOKEN` | 3 | 5442 | 0.1% |
| `PERSIST_CRON` | 2 | 5442 | 0.0% |
| `SHELL_DESTRUCTIVE` | 2 | 5442 | 0.0% |
| `DL_CHAIN_FETCH_EXECUTE` | 1 | 5442 | 0.0% |
| `DL_PASSWORD_ARCHIVE` | 1 | 5442 | 0.0% |
| `DL_PIPE_TO_SHELL` | 1 | 5442 | 0.0% |
| `LICENSE_MISMATCH` | 1 | 5442 | 0.0% |
| `OBFUSC_ZERO_WIDTH` | 1 | 5442 | 0.0% |

## Declaration rate (H6)

H6: *almost no skill declares its permissions.* This is the number the whole project rests on. The null hypothesis is `>= 20% declare`; if the null holds, the declared-vs-observed product has no market (research/PROTOCOL.md §1).

| | count |
|---|---|
| scanned, declaration status known | 5442 |
| declare permissions | 386 |
| do not declare | 5056 |
| declaration rate | 7.1% |
| H6 null (>= 20%) | rejected at this sample |

## Declared vs observed, among skills that declare

A `MISMATCH_*` finding is only possible where something was declared, so its prevalence over every scanned skill is divided by the declaration rate. With a declaration rate of a few percent that understates it by more than an order of magnitude. The denominator below is the skills that declare any permission, which is the population the product can actually say anything about.

| rule | hits | n (declarers) | prevalence |
|---|---|---|---|
| `MISMATCH_UNDER_DECLARED` | 76 | 386 | 19.7% |
| `MISMATCH_OVER_DECLARED` | 22 | 386 | 5.7% |

`MISMATCH_CONFLICTING` fired on no declaring skill in this corpus. That is a statement about the corpus, not evidence the rule is dead: it has unit tests, and its population is smaller than the declaration rate suggests.

## Stratified prevalence

Every headline figure must be reported per stratum (protocol §4.2); without stratification the result is dominated by one category.

### by `layer`

| value | n | failed | top rules |
|---|---|---|---|
| L3 | 5442 | 0 | `LICENSE_MISSING` 21.1%, `NET_DOMAIN_LITERAL` 6.7%, `SHELL_EXEC` 6.3%, `PI_DESCRIPTION_MISMATCH` 3.9%, `NET_FETCH_CALL` 3.0% |
### by `size`

| value | n | failed | top rules |
|---|---|---|---|
| 32k_128k | 720 | 0 | `NET_DOMAIN_LITERAL` 18.3%, `SHELL_EXEC` 16.5%, `LICENSE_MISSING` 14.6%, `PI_DESCRIPTION_MISMATCH` 10.3%, `FS_PATH_ESCAPE` 8.8% |
| 8k_32k | 1537 | 0 | `LICENSE_MISSING` 24.7%, `NET_DOMAIN_LITERAL` 5.0%, `SHELL_EXEC` 4.2%, `PI_DESCRIPTION_MISMATCH` 3.4%, `FS_PATH_ESCAPE` 2.6% |
| gt_128k | 306 | 0 | `SHELL_EXEC` 47.4%, `NET_DOMAIN_LITERAL` 42.8%, `PI_DESCRIPTION_MISMATCH` 25.2%, `FS_RECURSIVE_WALK` 24.8%, `NET_FETCH_CALL` 20.9% |
| lt_8k | 2879 | 0 | `LICENSE_MISSING` 21.8%, `PARSE_FAILED` 1.1%, `NET_DOMAIN_LITERAL` 0.8%, `MISMATCH_OVER_DECLARED` 0.5%, `SHELL_EXEC` 0.5% |
### by `scripts`

| value | n | failed | top rules |
|---|---|---|---|
| js | 305 | 0 | `NET_DOMAIN_LITERAL` 46.6%, `FS_PATH_ESCAPE` 33.4%, `SHELL_EXEC` 28.9%, `PI_DESCRIPTION_MISMATCH` 26.6%, `NET_FETCH_CALL` 23.6% |
| none | 4498 | 0 | `LICENSE_MISSING` 22.5%, `PARSE_FAILED` 1.3%, `OBFUSC_TRACKING_PIXEL` 0.4%, `LICENSE_RESTRICTIVE` 0.4%, `PI_CONCEALMENT` 0.4% |
| other | 5 | 0 | `NET_DOMAIN_LITERAL` 40.0%, `PI_DESCRIPTION_MISMATCH` 40.0%, `FS_HOME_ACCESS` 20.0%, `MISMATCH_UNDER_DECLARED` 20.0%, `NET_DYNAMIC_URL` 20.0% |
| python | 424 | 0 | `SHELL_EXEC` 37.3%, `NET_DOMAIN_LITERAL` 34.4%, `FS_RECURSIVE_WALK` 19.8%, `LICENSE_MISSING` 18.2%, `NET_FETCH_CALL` 16.0% |
| shell | 210 | 0 | `SHELL_EXEC` 46.2%, `NET_DOMAIN_LITERAL` 34.3%, `PI_DESCRIPTION_MISMATCH` 26.7%, `LICENSE_MISSING` 23.3%, `NET_HTTP_CLIENT` 23.3% |
### by `declared`

| value | n | failed | top rules |
|---|---|---|---|
| none | 5056 | 0 | `LICENSE_MISSING` 21.2%, `NET_DOMAIN_LITERAL` 6.6%, `SHELL_EXEC` 6.1%, `PI_DESCRIPTION_MISMATCH` 3.6%, `NET_FETCH_CALL` 2.9% |
| present | 386 | 0 | `MISMATCH_UNDER_DECLARED` 19.7%, `LICENSE_MISSING` 19.4%, `SHELL_EXEC` 9.6%, `PI_DESCRIPTION_MISMATCH` 8.3%, `NET_DOMAIN_LITERAL` 7.0% |
### by `license`

| value | n | failed | top rules |
|---|---|---|---|
| absent | 4797 | 0 | `LICENSE_MISSING` 23.9%, `NET_DOMAIN_LITERAL` 5.6%, `SHELL_EXEC` 4.3%, `PI_DESCRIPTION_MISMATCH` 3.5%, `FS_PATH_ESCAPE` 2.5% |
| present | 645 | 0 | `SHELL_EXEC` 21.4%, `NET_DOMAIN_LITERAL` 14.7%, `FS_RECURSIVE_WALK` 10.4%, `FS_HOME_ACCESS` 7.9%, `NET_FETCH_CALL` 7.6% |

## Precision and recall (GOLD)

Gate G4: precision >= 0.85 and recall >= 0.60, per rule (no micro-average).

| rule | TP | FP | missed | precision | recall | G4 |
|---|---|---|---|---|---|---|
| `DEP_CUSTOM_REGISTRY` | 6 | 0 | 0 | 100.0% | 100.0% | pass |
| `DEP_UNPINNED_SCRIPT` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `DL_CHAIN_FETCH_EXECUTE` | 1 | 0 | 0 | 100.0% | 100.0% | pass |
| `DL_PASSWORD_ARCHIVE` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_PIPE_TO_SHELL` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_REMOTE_INSTALL` | 3 | 1 | 0 | 75.0% | 100.0% | below |
| `DL_UNTRUSTED_DOMAIN` | 2 | 4 | 0 | 33.3% | 100.0% | below |
| `FS_ABSOLUTE_PATH` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `FS_HOME_ACCESS` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_MODE_UNRESOLVED` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_PATH_ESCAPE` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_RECURSIVE_WALK` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_SENSITIVE_PATH` | 4 | 0 | 0 | 100.0% | 100.0% | pass |
| `LICENSE_RESTRICTIVE` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `NET_DOMAIN_LITERAL` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `NET_DYNAMIC_URL` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `NET_FETCH_CALL` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `NET_HTTP_CLIENT` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `OBFUSC_TRACKING_PIXEL` | 6 | 2 | 0 | 75.0% | 100.0% | below |
| `OBFUSC_ZERO_WIDTH` | 1 | 0 | 0 | 100.0% | 100.0% | pass |
| `PERSIST_AGENT_CONFIG` | 6 | 2 | 0 | 75.0% | 100.0% | below |
| `PERSIST_CRON` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `PERSIST_HOOK` | 1 | 2 | 0 | 33.3% | 100.0% | below |
| `PERSIST_SHELL_RC` | 1 | 3 | 0 | 25.0% | 100.0% | below |
| `PI_CONCEALMENT` | 2 | 6 | 0 | 25.0% | 100.0% | below |
| `PI_EXFIL_INSTRUCTION` | 0 | 7 | 0 | 0.0% | n/a | below |
| `PI_INJECTION_OVERRIDE` | 1 | 7 | 0 | 12.5% | 100.0% | below |
| `PI_SYSTEM_IMPERSONATION` | 2 | 4 | 0 | 33.3% | 100.0% | below |
| `SECRET_ENV_DUMP` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `SECRET_GENERIC_ASSIGN` | 3 | 1 | 0 | 75.0% | 100.0% | below |
| `SECRET_PATH_READ` | 6 | 2 | 0 | 75.0% | 100.0% | below |
| `SECRET_PROVIDER_TOKEN` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `SHELL_DESTRUCTIVE` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `SHELL_EVAL` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `SHELL_EXEC` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `SHELL_PRIVILEGE_ESCALATION` | 2 | 6 | 0 | 25.0% | 100.0% | below |

If precision falls short, publish the measured value as an upper bound on true prevalence rather than widening the definition to hit a target.

## Limitations

- Static analysis cannot see semantic prompt injection; the miss rate is unknown.
- A clean scan is not a clean skill. Read the evidence.
- Registry sources whose operators have not cleared collection are absent from this report, and that absence is stated rather than worked around (protocol §3, R-4).
- **Two rules are unmeasurable at this collection scale, and their absence from the table is not evidence about the ecosystem.** `RESOURCE_LIMIT_EXCEEDED` trips at 10,000 files, 64 MB or depth 12, while the collector refuses anything over 80 files or 1.5 MB — so the corpus cannot contain a skill that reaches it. `FS_SYMLINK_OUTSIDE` needs a symlink, and the collector fetches file contents from a commit, so the corpus contains none. Both have fixture coverage; neither can be given a prevalence figure here.
