# SkillGuard Phase 0 corpus report

> **This is a pilot, not the pre-registered study.** The sample is an
> opportunistic GitHub code-search slice, not the stratified N=100,000 draw in
> `research/PROTOCOL.md` §5, and there is no GOLD label set yet, so the report
> contains **no precision or recall figure**. Read the numbers as a first signal
> and a proof that the pipeline runs on real data, not as the study's result.
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
> ## GOLD-v5
>
> The precision column below is measured against `research/gold/GOLD-v5.jsonl`:
> 250 line-level findings from the **current** rule set, judged `tp`/`fp` by two
> independent sessions of `opencode-go/deepseek-v4.1-flash` (no human, and not
> the rule author). Cohen's kappa is **0.949**; 6 disagreements adjudicated.
>
> Where the earlier passes did their job: `NET_FETCH_CALL` 100%,
> `NET_HTTP_CLIENT` 87.5%, `FS_PATH_ESCAPE` 87.5%, `NET_DYNAMIC_URL` 100%
> (`NET_FETCH_CALL` was 37.5% in GOLD-v1).
>
> Where they did not: the **prompt-injection rules are 0%** —
> `PI_CONCEALMENT`, `PI_EXFIL_INSTRUCTION` and `PI_INJECTION_OVERRIDE` are 0/8
> each. Every sampled finding was a false positive, because the corpus is full of
> security *training* material that discusses injection. Three suppression passes
> (quoted phrases, documentation structure, meta-discussion) cut their prevalence
> by half but did not lift precision, so **they are now `Info`**: a false
> `Critical` is worse than no finding. They still force a human to read the line;
> they no longer block a gate. `PERSIST_HOOK` (12.5%), `PERSIST_SHELL_RC` (0%)
> and `DEP_CUSTOM_REGISTRY` (12.5%) are next. Treat every prevalence figure below
> as an upper bound.
>
> (GOLD-v1..v3 are kept in `research/gold/`. Versions are not directly
> comparable: both the raters and the rule set change.)
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
> The remaining `PI_*` heuristics are **unmeasured upper bounds**. A
> single-annotator read-through is not `GOLD` (research/GOLD.md) and the report
> publishes no precision until two independent annotators agree (kappa >= 0.75).

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

Rule set version: `0.1.0`.

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
| `LICENSE_MISSING` | 1153 | 5442 | 21.2% |
| `SHELL_EXEC` | 422 | 5442 | 7.8% |
| `NET_DOMAIN_LITERAL` | 383 | 5442 | 7.0% |
| `PI_DESCRIPTION_MISMATCH` | 257 | 5442 | 4.7% |
| `NET_FETCH_CALL` | 164 | 5442 | 3.0% |
| `FS_RECURSIVE_WALK` | 148 | 5442 | 2.7% |
| `FS_PATH_ESCAPE` | 141 | 5442 | 2.6% |
| `FS_HOME_ACCESS` | 123 | 5442 | 2.3% |
| `MISMATCH_UNDER_DECLARED` | 82 | 5442 | 1.5% |
| `FS_ABSOLUTE_PATH` | 78 | 5442 | 1.4% |
| `PARSE_FAILED` | 71 | 5442 | 1.3% |
| `SECRET_ENV_DUMP` | 64 | 5442 | 1.2% |
| `NET_HTTP_CLIENT` | 53 | 5442 | 1.0% |
| `LICENSE_RESTRICTIVE` | 52 | 5442 | 1.0% |
| `SECRET_GENERIC_ASSIGN` | 36 | 5442 | 0.7% |
| `OBFUSC_TRACKING_PIXEL` | 33 | 5442 | 0.6% |
| `DL_UNTRUSTED_DOMAIN` | 29 | 5442 | 0.5% |
| `PI_CONCEALMENT` | 29 | 5442 | 0.5% |
| `NET_DYNAMIC_URL` | 24 | 5442 | 0.4% |
| `MISMATCH_OVER_DECLARED` | 22 | 5442 | 0.4% |
| `FS_SENSITIVE_PATH` | 16 | 5442 | 0.3% |
| `SHELL_EVAL` | 15 | 5442 | 0.3% |
| `SHELL_PRIVILEGE_ESCALATION` | 14 | 5442 | 0.3% |
| `DEP_CUSTOM_REGISTRY` | 12 | 5442 | 0.2% |
| `PERSIST_AGENT_CONFIG` | 10 | 5442 | 0.2% |
| `PI_INJECTION_OVERRIDE` | 10 | 5442 | 0.2% |
| `PI_EXFIL_INSTRUCTION` | 7 | 5442 | 0.1% |
| `DL_REMOTE_INSTALL` | 6 | 5442 | 0.1% |
| `PERSIST_HOOK` | 6 | 5442 | 0.1% |
| `PI_SYSTEM_IMPERSATION` | 6 | 5442 | 0.1% |
| `SECRET_PROVIDER_TOKEN` | 6 | 5442 | 0.1% |
| `SECRET_PRIVATE_KEY` | 4 | 5442 | 0.1% |
| `DEP_UNPINNED_SCRIPT` | 3 | 5442 | 0.1% |
| `FS_MODE_UNRESOLVED` | 3 | 5442 | 0.1% |
| `PERSIST_CRON` | 2 | 5442 | 0.0% |
| `SECRET_PATH_READ` | 2 | 5442 | 0.0% |
| `SHELL_DESTRUCTIVE` | 2 | 5442 | 0.0% |
| `DL_CHAIN_FETCH_EXECUTE` | 1 | 5442 | 0.0% |
| `DL_PASSWORD_ARCHIVE` | 1 | 5442 | 0.0% |
| `DL_PIPE_TO_SHELL` | 1 | 5442 | 0.0% |
| `LICENSE_MISMATCH` | 1 | 5442 | 0.0% |
| `OBFUSC_ZERO_WIDTH` | 1 | 5442 | 0.0% |
| `PERSIST_SHELL_RC` | 1 | 5442 | 0.0% |

## Declaration rate (H6)

H6: *almost no skill declares its permissions.* This is the number the whole project rests on. The null hypothesis is `>= 20% declare`; if the null holds, the declared-vs-observed product has no market (research/PROTOCOL.md §1).

| | count |
|---|---|
| scanned, declaration status known | 5442 |
| declare permissions | 386 |
| do not declare | 5056 |
| declaration rate | 7.1% |
| H6 null (>= 20%) | rejected at this sample |

## Stratified prevalence

Every headline figure must be reported per stratum (protocol §4.2); without stratification the result is dominated by one category.

### by `layer`

| value | n | failed | top rules |
|---|---|---|---|
| L3 | 5442 | 0 | `LICENSE_MISSING` 21.2%, `SHELL_EXEC` 7.8%, `NET_DOMAIN_LITERAL` 7.0%, `PI_DESCRIPTION_MISMATCH` 4.7%, `NET_FETCH_CALL` 3.0% |
### by `size`

| value | n | failed | top rules |
|---|---|---|---|
| 32k_128k | 720 | 0 | `SHELL_EXEC` 20.8%, `NET_DOMAIN_LITERAL` 19.0%, `LICENSE_MISSING` 14.7%, `PI_DESCRIPTION_MISMATCH` 12.2%, `FS_PATH_ESCAPE` 8.9% |
| 8k_32k | 1537 | 0 | `LICENSE_MISSING` 24.8%, `SHELL_EXEC` 5.7%, `NET_DOMAIN_LITERAL` 5.1%, `PI_DESCRIPTION_MISMATCH` 4.4%, `FS_PATH_ESCAPE` 2.7% |
| gt_128k | 306 | 0 | `SHELL_EXEC` 54.2%, `NET_DOMAIN_LITERAL` 46.7%, `PI_DESCRIPTION_MISMATCH` 30.7%, `FS_RECURSIVE_WALK` 26.5%, `NET_FETCH_CALL` 20.9% |
| lt_8k | 2879 | 0 | `LICENSE_MISSING` 21.9%, `PARSE_FAILED` 1.0%, `NET_DOMAIN_LITERAL` 0.9%, `SHELL_EXEC` 0.6%, `MISMATCH_OVER_DECLARED` 0.5% |
### by `scripts`

| value | n | failed | top rules |
|---|---|---|---|
| js | 305 | 0 | `NET_DOMAIN_LITERAL` 46.9%, `FS_PATH_ESCAPE` 33.4%, `SHELL_EXEC` 32.5%, `PI_DESCRIPTION_MISMATCH` 29.8%, `NET_FETCH_CALL` 23.6% |
| none | 4498 | 0 | `LICENSE_MISSING` 22.6%, `PARSE_FAILED` 1.2%, `OBFUSC_TRACKING_PIXEL` 0.4%, `LICENSE_RESTRICTIVE` 0.4%, `PI_CONCEALMENT` 0.4% |
| other | 5 | 0 | `PI_DESCRIPTION_MISMATCH` 60.0%, `NET_DOMAIN_LITERAL` 40.0%, `SECRET_GENERIC_ASSIGN` 40.0%, `FS_HOME_ACCESS` 20.0%, `MISMATCH_UNDER_DECLARED` 20.0% |
| python | 424 | 0 | `SHELL_EXEC` 51.7%, `NET_DOMAIN_LITERAL` 38.9%, `FS_RECURSIVE_WALK` 22.4%, `PI_DESCRIPTION_MISMATCH` 19.3%, `LICENSE_MISSING` 18.2% |
| shell | 210 | 0 | `SHELL_EXEC` 49.5%, `NET_DOMAIN_LITERAL` 34.3%, `PI_DESCRIPTION_MISMATCH` 31.0%, `FS_RECURSIVE_WALK` 23.3%, `LICENSE_MISSING` 23.3% |
### by `declared`

| value | n | failed | top rules |
|---|---|---|---|
| none | 5056 | 0 | `LICENSE_MISSING` 21.3%, `SHELL_EXEC` 7.4%, `NET_DOMAIN_LITERAL` 7.0%, `PI_DESCRIPTION_MISMATCH` 4.3%, `NET_FETCH_CALL` 2.9% |
| present | 386 | 0 | `MISMATCH_UNDER_DECLARED` 21.2%, `LICENSE_MISSING` 19.4%, `SHELL_EXEC` 11.9%, `PI_DESCRIPTION_MISMATCH` 10.6%, `NET_DOMAIN_LITERAL` 7.5% |
### by `license`

| value | n | failed | top rules |
|---|---|---|---|
| absent | 4797 | 0 | `LICENSE_MISSING` 24.0%, `NET_DOMAIN_LITERAL` 5.8%, `SHELL_EXEC` 5.5%, `PI_DESCRIPTION_MISMATCH` 4.0%, `FS_PATH_ESCAPE` 2.5% |
| present | 645 | 0 | `SHELL_EXEC` 24.3%, `NET_DOMAIN_LITERAL` 16.6%, `FS_RECURSIVE_WALK` 10.9%, `PI_DESCRIPTION_MISMATCH` 9.9%, `FS_HOME_ACCESS` 8.7% |

## Precision and recall (GOLD)

Gate G4: precision >= 0.85 and recall >= 0.60, per rule (no micro-average).

| rule | TP | FP | missed | precision | recall | G4 |
|---|---|---|---|---|---|---|
| `DEP_CUSTOM_REGISTRY` | 1 | 2 | 0 | 33.3% | 100.0% | below |
| `DEP_UNPINNED_SCRIPT` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `DL_CHAIN_FETCH_EXECUTE` | 1 | 0 | 0 | 100.0% | 100.0% | pass |
| `DL_PASSWORD_ARCHIVE` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_PIPE_TO_SHELL` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_REMOTE_INSTALL` | 1 | 5 | 0 | 16.7% | 100.0% | below |
| `DL_UNTRUSTED_DOMAIN` | 1 | 7 | 0 | 12.5% | 100.0% | below |
| `FS_ABSOLUTE_PATH` | 3 | 1 | 0 | 75.0% | 100.0% | below |
| `FS_HOME_ACCESS` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `FS_MODE_UNRESOLVED` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_PATH_ESCAPE` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `FS_RECURSIVE_WALK` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_SENSITIVE_PATH` | 2 | 6 | 0 | 25.0% | 100.0% | below |
| `LICENSE_RESTRICTIVE` | 5 | 3 | 0 | 62.5% | 100.0% | below |
| `NET_DOMAIN_LITERAL` | 5 | 2 | 0 | 71.4% | 100.0% | below |
| `NET_DYNAMIC_URL` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `NET_FETCH_CALL` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `NET_HTTP_CLIENT` | 6 | 1 | 0 | 85.7% | 100.0% | pass |
| `OBFUSC_TRACKING_PIXEL` | 4 | 2 | 0 | 66.7% | 100.0% | below |
| `OBFUSC_ZERO_WIDTH` | 1 | 0 | 0 | 100.0% | 100.0% | pass |
| `PERSIST_AGENT_CONFIG` | 1 | 4 | 0 | 20.0% | 100.0% | below |
| `PERSIST_CRON` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `PERSIST_HOOK` | 0 | 3 | 0 | 0.0% | n/a | below |
| `PERSIST_SHELL_RC` | 0 | 1 | 0 | 0.0% | n/a | below |
| `PI_CONCEALMENT` | 0 | 4 | 0 | 0.0% | n/a | below |
| `PI_EXFIL_INSTRUCTION` | 0 | 2 | 0 | 0.0% | n/a | below |
| `PI_INJECTION_OVERRIDE` | 0 | 2 | 0 | 0.0% | n/a | below |
| `PI_SYSTEM_IMPERSATION` | 1 | 4 | 0 | 20.0% | 100.0% | below |
| `SECRET_ENV_DUMP` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `SECRET_GENERIC_ASSIGN` | 1 | 7 | 0 | 12.5% | 100.0% | below |
| `SECRET_PRIVATE_KEY` | 0 | 4 | 0 | 0.0% | n/a | below |
| `SECRET_PROVIDER_TOKEN` | 2 | 4 | 0 | 33.3% | 100.0% | below |
| `SHELL_DESTRUCTIVE` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `SHELL_EVAL` | 3 | 5 | 0 | 37.5% | 100.0% | below |
| `SHELL_EXEC` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `SHELL_PRIVILEGE_ESCALATION` | 0 | 8 | 0 | 0.0% | n/a | below |

If precision falls short, publish the measured value as an upper bound on true prevalence rather than widening the definition to hit a target.

## Limitations

- Static analysis cannot see semantic prompt injection; the miss rate is unknown.
- A clean scan is not a clean skill. Read the evidence.
- Registry sources whose operators have not cleared collection are absent from this report, and that absence is stated rather than worked around (protocol §3, R-4).
