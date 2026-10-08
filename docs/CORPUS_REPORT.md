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
> ## GOLD-v4
>
> The precision column below is measured against `research/gold/GOLD-v4.jsonl`:
> 151 line-level findings, judged `tp`/`fp` by **two independent sessions** of
> `opencode-go/deepseek-v4.1-flash` (no human, and not the rule author). Cohen's
> kappa is **0.907**.
>
> This round fixed the last four rules' substring matching. `FS_ABSOLUTE_PATH`
> matched `/dev/` inside `/dev/null`; `FS_SENSITIVE_PATH` matched `read` inside
> `README` and `Readonly`; `DL_BASE64_BLOB` matched long lowercase paths; and a
> `# ...` after code was not treated as a comment. `FS_ABSOLUTE_PATH` rose
> `25% -> 50%`, `PERSIST_HOOK` `12.5% -> 66.7%`, and `DL_BASE64_BLOB` left the
> table.
>
> `FS_HOME_ACCESS` reads 100%, but that is a **tautology**: its claim is only
> that the home directory is "referenced", which any `~/` mention satisfies, and
> the two annotators disagreed on six of its eight items. The claim must be
> reworded to "accessed" before the number means anything. Treat every
> prevalence figure below as an upper bound.
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
| `NET_DOMAIN_LITERAL` | 411 | 5442 | 7.6% |
| `PI_DESCRIPTION_MISMATCH` | 347 | 5442 | 6.4% |
| `NET_FETCH_CALL` | 169 | 5442 | 3.1% |
| `FS_RECURSIVE_WALK` | 148 | 5442 | 2.7% |
| `FS_PATH_ESCAPE` | 141 | 5442 | 2.6% |
| `FS_ABSOLUTE_PATH` | 123 | 5442 | 2.3% |
| `FS_HOME_ACCESS` | 123 | 5442 | 2.3% |
| `MISMATCH_UNDER_DECLARED` | 82 | 5442 | 1.5% |
| `SHELL_EXEC` | 75 | 5442 | 1.4% |
| `PARSE_FAILED` | 71 | 5442 | 1.3% |
| `NET_HTTP_CLIENT` | 69 | 5442 | 1.3% |
| `SECRET_ENV_DUMP` | 64 | 5442 | 1.2% |
| `LICENSE_RESTRICTIVE` | 52 | 5442 | 1.0% |
| `PI_CONCEALMENT` | 50 | 5442 | 0.9% |
| `OBFUSC_TRACKING_PIXEL` | 39 | 5442 | 0.7% |
| `SECRET_GENERIC_ASSIGN` | 36 | 5442 | 0.7% |
| `DL_UNTRUSTED_DOMAIN` | 29 | 5442 | 0.5% |
| `DL_PASSWORD_ARCHIVE` | 26 | 5442 | 0.5% |
| `DEP_CUSTOM_REGISTRY` | 24 | 5442 | 0.4% |
| `NET_DYNAMIC_URL` | 24 | 5442 | 0.4% |
| `PI_INJECTION_OVERRIDE` | 24 | 5442 | 0.4% |
| `MISMATCH_OVER_DECLARED` | 22 | 5442 | 0.4% |
| `SHELL_EVAL` | 20 | 5442 | 0.4% |
| `PERSIST_AGENT_CONFIG` | 17 | 5442 | 0.3% |
| `SECRET_PATH_READ` | 17 | 5442 | 0.3% |
| `FS_SENSITIVE_PATH` | 16 | 5442 | 0.3% |
| `PI_EXFIL_INSTRUCTION` | 15 | 5442 | 0.3% |
| `SHELL_PRIVILEGE_ESCALATION` | 14 | 5442 | 0.3% |
| `PERSIST_HOOK` | 11 | 5442 | 0.2% |
| `PI_SYSTEM_IMPERSATION` | 11 | 5442 | 0.2% |
| `SHELL_DESTRUCTIVE` | 8 | 5442 | 0.1% |
| `DL_PIPE_TO_SHELL` | 6 | 5442 | 0.1% |
| `DL_REMOTE_INSTALL` | 6 | 5442 | 0.1% |
| `SECRET_PROVIDER_TOKEN` | 6 | 5442 | 0.1% |
| `PERSIST_SHELL_RC` | 5 | 5442 | 0.1% |
| `PERSIST_CRON` | 4 | 5442 | 0.1% |
| `SECRET_PRIVATE_KEY` | 4 | 5442 | 0.1% |
| `DEP_UNPINNED_SCRIPT` | 3 | 5442 | 0.1% |
| `FS_MODE_UNRESOLVED` | 3 | 5442 | 0.1% |
| `OBFUSC_ZERO_WIDTH` | 3 | 5442 | 0.1% |
| `SECRET_AWS_ACCESS_KEY` | 3 | 5442 | 0.1% |
| `DL_CHAIN_FETCH_EXECUTE` | 1 | 5442 | 0.0% |
| `LICENSE_MISMATCH` | 1 | 5442 | 0.0% |

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
| L3 | 5442 | 0 | `LICENSE_MISSING` 21.2%, `NET_DOMAIN_LITERAL` 7.6%, `PI_DESCRIPTION_MISMATCH` 6.4%, `NET_FETCH_CALL` 3.1%, `FS_RECURSIVE_WALK` 2.7% |
### by `size`

| value | n | failed | top rules |
|---|---|---|---|
| 32k_128k | 720 | 0 | `NET_DOMAIN_LITERAL` 20.4%, `PI_DESCRIPTION_MISMATCH` 14.9%, `LICENSE_MISSING` 14.7%, `FS_PATH_ESCAPE` 8.9%, `NET_FETCH_CALL` 8.2% |
| 8k_32k | 1537 | 0 | `LICENSE_MISSING` 24.8%, `NET_DOMAIN_LITERAL` 6.1%, `PI_DESCRIPTION_MISMATCH` 5.8%, `FS_PATH_ESCAPE` 2.7%, `MISMATCH_UNDER_DECLARED` 2.5% |
| gt_128k | 306 | 0 | `NET_DOMAIN_LITERAL` 47.7%, `PI_DESCRIPTION_MISMATCH` 40.2%, `FS_RECURSIVE_WALK` 26.5%, `NET_FETCH_CALL` 21.6%, `FS_HOME_ACCESS` 19.0% |
| lt_8k | 2879 | 0 | `LICENSE_MISSING` 21.9%, `PARSE_FAILED` 1.0%, `PI_DESCRIPTION_MISMATCH` 1.0%, `NET_DOMAIN_LITERAL` 0.9%, `PI_CONCEALMENT` 0.6% |
### by `scripts`

| value | n | failed | top rules |
|---|---|---|---|
| js | 305 | 0 | `NET_DOMAIN_LITERAL` 50.5%, `FS_PATH_ESCAPE` 33.4%, `PI_DESCRIPTION_MISMATCH` 30.5%, `NET_FETCH_CALL` 23.6%, `MISMATCH_UNDER_DECLARED` 14.4% |
| none | 4498 | 0 | `LICENSE_MISSING` 22.6%, `PI_DESCRIPTION_MISMATCH` 1.6%, `PARSE_FAILED` 1.2%, `PI_CONCEALMENT` 0.8%, `OBFUSC_TRACKING_PIXEL` 0.5% |
| other | 5 | 0 | `PI_DESCRIPTION_MISMATCH` 60.0%, `NET_DOMAIN_LITERAL` 40.0%, `SECRET_GENERIC_ASSIGN` 40.0%, `FS_HOME_ACCESS` 20.0%, `MISMATCH_UNDER_DECLARED` 20.0% |
| python | 424 | 0 | `NET_DOMAIN_LITERAL` 42.5%, `PI_DESCRIPTION_MISMATCH` 25.7%, `FS_RECURSIVE_WALK` 22.4%, `LICENSE_MISSING` 18.2%, `NET_FETCH_CALL` 16.7% |
| shell | 210 | 0 | `NET_DOMAIN_LITERAL` 35.2%, `PI_DESCRIPTION_MISMATCH` 32.9%, `NET_HTTP_CLIENT` 26.7%, `SHELL_EXEC` 25.7%, `FS_RECURSIVE_WALK` 23.3% |
### by `declared`

| value | n | failed | top rules |
|---|---|---|---|
| none | 5056 | 0 | `LICENSE_MISSING` 21.3%, `NET_DOMAIN_LITERAL` 7.4%, `PI_DESCRIPTION_MISMATCH` 5.8%, `NET_FETCH_CALL` 3.0%, `FS_RECURSIVE_WALK` 2.8% |
| present | 386 | 0 | `MISMATCH_UNDER_DECLARED` 21.2%, `LICENSE_MISSING` 19.4%, `PI_DESCRIPTION_MISMATCH` 13.7%, `NET_DOMAIN_LITERAL` 10.1%, `MISMATCH_OVER_DECLARED` 5.7% |
### by `license`

| value | n | failed | top rules |
|---|---|---|---|
| absent | 4797 | 0 | `LICENSE_MISSING` 24.0%, `NET_DOMAIN_LITERAL` 6.1%, `PI_DESCRIPTION_MISMATCH` 5.0%, `FS_PATH_ESCAPE` 2.5%, `NET_FETCH_CALL` 2.5% |
| present | 645 | 0 | `NET_DOMAIN_LITERAL` 18.1%, `PI_DESCRIPTION_MISMATCH` 16.6%, `FS_RECURSIVE_WALK` 10.9%, `FS_HOME_ACCESS` 8.7%, `NET_FETCH_CALL` 7.6% |

## Precision and recall (GOLD)

Gate G4: precision >= 0.85 and recall >= 0.60, per rule (no micro-average).

| rule | TP | FP | missed | precision | recall | G4 |
|---|---|---|---|---|---|---|
| `DEP_CUSTOM_REGISTRY` | 0 | 2 | 0 | 0.0% | n/a | below |
| `DEP_UNPINNED_SCRIPT` | 2 | 0 | 0 | 100.0% | 100.0% | pass |
| `DL_PASSWORD_ARCHIVE` | 0 | 3 | 0 | 0.0% | n/a | below |
| `DL_PIPE_TO_SHELL` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_REMOTE_INSTALL` | 0 | 1 | 0 | 0.0% | n/a | below |
| `DL_UNTRUSTED_DOMAIN` | 2 | 6 | 0 | 25.0% | 100.0% | below |
| `FS_ABSOLUTE_PATH` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `FS_HOME_ACCESS` | 8 | 0 | 0 | 100.0% | 100.0% | pass |
| `FS_PATH_ESCAPE` | 6 | 2 | 0 | 75.0% | 100.0% | below |
| `FS_RECURSIVE_WALK` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `FS_SENSITIVE_PATH` | 1 | 4 | 0 | 20.0% | 100.0% | below |
| `LICENSE_RESTRICTIVE` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `NET_DOMAIN_LITERAL` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `NET_DYNAMIC_URL` | 3 | 0 | 0 | 100.0% | 100.0% | pass |
| `NET_FETCH_CALL` | 7 | 1 | 0 | 87.5% | 100.0% | pass |
| `NET_HTTP_CLIENT` | 5 | 3 | 0 | 62.5% | 100.0% | below |
| `OBFUSC_TRACKING_PIXEL` | 6 | 2 | 0 | 75.0% | 100.0% | below |
| `PERSIST_AGENT_CONFIG` | 1 | 4 | 0 | 20.0% | 100.0% | below |
| `PERSIST_CRON` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `PERSIST_HOOK` | 2 | 1 | 0 | 66.7% | 100.0% | below |
| `PI_CONCEALMENT` | 0 | 4 | 0 | 0.0% | n/a | below |
| `PI_EXFIL_INSTRUCTION` | 0 | 3 | 0 | 0.0% | n/a | below |
| `PI_INJECTION_OVERRIDE` | 0 | 2 | 0 | 0.0% | n/a | below |
| `PI_SYSTEM_IMPERSATION` | 0 | 2 | 0 | 0.0% | n/a | below |
| `SECRET_AWS_ACCESS_KEY` | 0 | 1 | 0 | 0.0% | n/a | below |
| `SECRET_ENV_DUMP` | 5 | 3 | 0 | 62.5% | 100.0% | below |
| `SECRET_GENERIC_ASSIGN` | 1 | 1 | 0 | 50.0% | 100.0% | below |
| `SECRET_PATH_READ` | 0 | 1 | 0 | 0.0% | n/a | below |
| `SECRET_PRIVATE_KEY` | 0 | 3 | 0 | 0.0% | n/a | below |
| `SECRET_PROVIDER_TOKEN` | 0 | 1 | 0 | 0.0% | n/a | below |
| `SHELL_DESTRUCTIVE` | 1 | 2 | 0 | 33.3% | 100.0% | below |
| `SHELL_EVAL` | 1 | 3 | 0 | 25.0% | 100.0% | below |
| `SHELL_EXEC` | 4 | 4 | 0 | 50.0% | 100.0% | below |
| `SHELL_PRIVILEGE_ESCALATION` | 1 | 1 | 0 | 50.0% | 100.0% | below |

If precision falls short, publish the measured value as an upper bound on true prevalence rather than widening the definition to hit a target.

## Limitations

- Static analysis cannot see semantic prompt injection; the miss rate is unknown.
- A clean scan is not a clean skill. Read the evidence.
- Registry sources whose operators have not cleared collection are absent from this report, and that absence is stated rather than worked around (protocol §3, R-4).
