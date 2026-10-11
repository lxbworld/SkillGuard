# GOLD labelling runbook

`research/PROTOCOL.md` §7 requires ground truth before any precision or recall
figure is published: a hand-labelled sample, **two independent annotators blind
to rule output**, and **Cohen's κ ≥ 0.75**. This is the runbook for one round
(`GOLD-v1`). It is the last missing piece before the report can carry a real
precision column.

The pilot report currently says "no precision". That is deliberate: a
single-annotator read-through found and fixed a dozen false-positive rules, but
it is not G4 and it is not published as a metric.

## 1. Draw the sample

A GOLD sample is a **stratified random draw from the scanned corpus**, not the
findings it produced — otherwise rules that fire rarely are never checked, and
recall cannot be measured at all.

```bash
# candidate rows: the scanned manifest, stratified as in PROTOCOL.md §5
skillguard corpus stats --findings research/raw-findings.jsonl --format json \
  > /tmp/stats.json
```

Take ~500 skills per stratum (`docs/PHASE0_CORPUS_STUDY.md` §4.3), recording the
sampling seed and the draw so it is reproducible. Oversized strata use
systematic sampling (`repository id mod k`), never a hand-picked subset.

## 2. Build two blind worksheets

One worksheet per annotator, identical content, **no rule output**. The scanner
can already emit the rules-free view:

```bash
skillguard inspect <skill-dir> --labeling
```

`research/make_precision_sample.py` wraps this into a working file for the
corpus; extend it to emit one file per annotator. A worksheet row looks like:

```json
{"source_id": "...", "rule": "NET_DOMAIN_LITERAL", "line": 12,
 "evidence": "<normalized text>", "context": "..."}
```

The worksheet contains third-party source, so it is **gitignored**
(`/research/gold/*.worksheet.jsonl`) and never published (R-2).

## 3. Label

Each annotator fills `verdict` for every row, independently and without seeing
the other's file or the rule's own output:

- `tp` — the rule is right: this is a real instance of what it claims.
- `fp` — the rule is wrong: this is not.
- `fn` — a row the rules **missed**: a real instance that produced no finding.

Labels are `{source_id, rule, verdict}` only — no payload — so a finished label
set **is** committed (`research/gold/GOLD-v1.<annotator>.jsonl`) and becomes the
project's permanent regression baseline.

## 4. Check agreement before anything else

```bash
skillguard corpus agreement \
    research/gold/GOLD-v1.annotator-a.jsonl \
    research/gold/GOLD-v1.annotator-b.jsonl
```

```
    rule                        n  agree  kappa
    NET_DOMAIN_LITERAL           4      2  0.000
    (all rules)                  4      2  0.000

    G3 gate (kappa >= 0.75): FAIL
```

- Only items **both** annotators rated are counted. A skipped item is neither
  agreement nor disagreement; scoring it as agreement is how a kappa number
  lies.
- `undefined` means there was no chance-corrected variance to measure (both
  annotators used one label throughout) — that is a defect in the sample, not
  perfect agreement.
- Exits `2` when the gate fails, so CI can refuse a release on it.

**If κ < 0.75, stop.** The rule definitions are defective (per
`research/PROTOCOL.md` §4.3): fix them, regenerate the worksheets and relabel.
Disagreements are adjudicated by a third party and the adjudication is recorded.

## 5. Score precision and recall

Once κ passes, the adjudicated label set (call it `GOLD-v1.jsonl`) drives the
report:

```bash
skillguard corpus report \
    --findings research/raw-findings.jsonl \
    --gold research/gold/GOLD-v1.jsonl \
    --out docs/CORPUS_REPORT.md
```

`score()` reports precision and recall **per rule**, never micro-averaged — a
micro-average lets a large rule hide a small broken one.

**Gate G4**: precision ≥ 0.85 and recall ≥ 0.60. If G4 fails, publish the
measured precision as an **upper bound** on true prevalence and say so. A
published 0.62 is worth more than an unpublished 0.95.

## 6. No post-hoc tuning

A GOLD version is frozen. Looking at the labels, changing a rule, and
re-reporting the same version is prohibited (`research/PROTOCOL.md` §7) — that
is how a precision number stops meaning anything. Rule changes go into a new
labelled version, `GOLD-v2`, and both versions are reported independently.

---

## GOLD-v1 (constructed)

| | |
|---|---|
| items | 193 findings (8 per rule, hash-ordered; one judgment per skill+rule) |
| frame | all line-level findings in the 1372-skill pilot |
| excluded | skill-level rules (`PARSE_FAILED`, `PI_DESCRIPTION_MISMATCH`) — no evidence line to judge |
| annotator A | `opencode-go/deepseek-v4.1-flash`, blind to the other label set |
| annotator B | the rule author |
| agreement | 174/193 (90.2%), **Cohen's κ 0.784** (gate 0.75) |
| disagreements | 19, adjudicated by the author |

Neither annotator is human. Both saw only the matched line, its context and the
rule's own `claim`. Annotator B wrote the rules, so this κ overstates what two
strangers would agree on, and the author adjudication of the 19 disputes is
biased the same way. It is a **screening** pass, not the protocol's human GOLD.

### Result

The precision column in `docs/CORPUS_REPORT.md` is the output. Most rules score
far below the G4 threshold of 0.85, and the failures share one cause: **the
patterns do not distinguish code from comments, documentation, docstrings and
string literals.** `NET_FETCH_CALL` fires on `import urllib.request` (an import
is not a request); `SHELL_EVAL` fires on `exec` inside `@app.command("eval")`;
`PERSIST_AGENT_CONFIG` fires on a comment that mentions `~/.claude/`;
`DL_UNTRUSTED_DOMAIN` fires on `Chrome/120.0.0.0` through its IPv4 pattern.

That is why prevalence is published as an upper bound. The next step is a
line-kind model (comment / string / code) and rules that require an *action*
rather than a mention; those changes belong in `GOLD-v2`.

### Reproduce

```bash
python3 research/build_gold.py        # rebuild the worksheet
# two annotators label it independently -> GOLD-v1.annotator-{a,b}.jsonl
skillguard corpus agreement research/gold/GOLD-v1.annotator-a.jsonl \
                            research/gold/GOLD-v1.annotator-b.jsonl
skillguard corpus report --findings research/raw-findings.jsonl \
    --gold research/gold/GOLD-v1.jsonl --out docs/CORPUS_REPORT.md
```

---

## GOLD-v2 (constructed)

GOLD-v1 drove rule changes (comment-line suppression for behavioural rules, a
`NET_FETCH_CALL` that requires a call rather than an import, zero-width
characters that must sit inside a word). A changed rule set invalidates
comparison, so those changes are measured as **GOLD-v2**.

| | |
|---|---|
| items | 183 line-level findings (8 per rule, hash-ordered) |
| annotator A / B | **two independent sessions of the same model** (`opencode-go/deepseek-v4.1-flash`), blind to each other |
| agreement | 169/183 (92.3%), **Cohen's κ 0.833** (gate 0.75) |
| disagreements | 14, adjudicated by the instruction both annotators were given |

Neither annotator is human, and this time **the rule author did not annotate**,
so there is no author anchoring. The two sessions are the same model, so κ is a
test–retest figure, not inter-model agreement.

### What changed

| rule | GOLD-v1 | GOLD-v2 | note |
|---|---|---|---|
| `NET_FETCH_CALL` | 37.5% | **87.5%** | now requires a call, not `import urllib.request` |
| `FS_HOME_ACCESS` | 25.0% | 50.0% | comment lines no longer fire |
| `NET_HTTP_CLIENT` | 50.0% | 62.5% | |
| `FS_PATH_ESCAPE` | 75.0% | 75.0% | unchanged |
| `FS_RECURSIVE_WALK` | 100% | 100% | unchanged |

The v1 and v2 columns are **not directly comparable** — the raters differ (v1
used one model plus the author; v2 uses two model sessions). The rule-attributable
change is `NET_FETCH_CALL`, whose false-positive source was removed by
construction and is covered by a regression test.

### What is still wrong

Most rules remain far below G4. The cause is the same as v1: patterns match
**mentions**. `PERSIST_AGENT_CONFIG` still fires on any line that names
`~/.claude/`, including `Write`/`read` helpers and documentation that survived
comment suppression. `NET_DOMAIN_LITERAL` still matches file extensions that
look like TLDs (`.sh`, `.app`, `.info`). `OBFUSC_HOMOGLYPH` still fires on
legitimate non-Latin prose. These need a *line-kind model* (comment / string /
code / prose) and patterns that require an action, and they are GOLD-v3 work.

---

## GOLD-v3 (constructed)

A third round of fixes followed the same pattern — make the rule require the
claimed action rather than a mention — and is measured as GOLD-v3.

| | |
|---|---|
| items | 162 line-level findings |
| annotators | two independent sessions of `opencode-go/deepseek-v4.1-flash`, blind to each other |
| agreement | 154/162 (95.1%), **Cohen's κ 0.898** |
| disagreements | 8, adjudicated by the annotators' shared instruction |

No human annotated, and the rule author did not annotate.

### What changed

| rule | GOLD-v2 | GOLD-v3 | note |
|---|---|---|---|
| `NET_DOMAIN_LITERAL` | 12.5% | **50.0%** | ambiguous TLDs need URL context; `comet-state.sh`/`logger.info` are filenames |
| `NET_FETCH_CALL` | 87.5% | 87.5% | holds |
| `NET_DYNAMIC_URL` | 100% | 100% | holds |
| `PERSIST_AGENT_CONFIG` | 0% | 20.0% | needs a write |
| `FS_RECURSIVE_WALK` | 100% | 87.5% | |
| `DL_BASE64_BLOB` | 37.5% | 12.5% | the credential-context suppression did not help the sampled items |

Prevalence fell with each fix (`NET_DOMAIN_LITERAL` 6.3% → 4.7%,
`PERSIST_AGENT_CONFIG` 1.4% → 0.4%, `OBFUSC_HOMOGLYPH` off the table), which is
what removing false positives should do.

### What is still wrong

Four rules sit at 25% or below and are the remaining work: `DL_BASE64_BLOB`,
`FS_ABSOLUTE_PATH`, `FS_HOME_ACCESS`, `FS_SENSITIVE_PATH`. All four still match a
substring (`/usr/`, `~/`, `.env`, a long base64 run) without requiring the
claimed action. `PI_*` rules have not been measured at all against a skill-level
sample — a line-level finding sample cannot measure "the description does not
match the behaviour".

---

## GOLD-v4 (constructed)

A fourth round, aimed at the last four rules that matched substrings without
requiring the claimed action.

| | |
|---|---|
| items | 151 line-level findings |
| annotators | two independent sessions of `opencode-go/deepseek-v4.1-flash` |
| agreement | 144/151 (95.4%), **Cohen's κ 0.907** |
| disagreements | 7, adjudicated by the annotators' shared instruction |

### What changed

| rule | GOLD-v3 | GOLD-v4 | note |
|---|---|---|---|
| `FS_ABSOLUTE_PATH` | 25.0% | **50.0%** | `/dev/null` was matched as `/dev/`; the check now reads the whole line |
| `PERSIST_HOOK` | 12.5% | 66.7% | |
| `FS_SENSITIVE_PATH` | 25.0% | 20.0% | `\b` around the verbs: `README` is not `read` |
| `DL_BASE64_BLOB` | 12.5% | off the table | a long lowercase path is not a payload |
| `FS_HOME_ACCESS` | 25.0% | 100% | **see the tautology below** |

### The `FS_HOME_ACCESS` tautology

The rule's claim is *"The home directory is referenced"*. Any line containing
`~/` satisfies that literally, so the two annotators disagreed on six of its
eight items and the adjudicated precision is 100% — which says nothing about
whether the rule is useful. The claim needs to be *"The home directory is
accessed (a config, cache or credential path)"* and the rule needs to require an
access, not a mention. Until then its number should be ignored. This is a good
example of why a rule's **claim wording is part of its definition**: a vague
claim makes an unmeasurable rule.

### Remaining

`PI_*` rules are still unmeasured: a line-level finding sample cannot measure
"the description does not match the behaviour". That needs a skill-level GOLD —
annotators read a whole skill and label capabilities, blind to rule output.

---

## SKILL-v1: a skill-level GOLD

A line-level finding sample cannot measure `PI_DESCRIPTION_MISMATCH`: its claim
is about a whole skill. `research/build_skill_gold.py` samples 30 skills
deterministically (skills flagged by the `PI_*`/network/shell/persistence rules,
plus quiet skills), emits the **normalized text with no rule output**, and two
independent model sessions answer a fixed questionnaire per skill (`network`,
`secrets`, `shell`, `injection`, `exfiltration`, `obfuscation`, `persistence`,
`understated`). `research/score_skill_gold.py` scores it.

| category | Cohen's κ |
|---|---|
| shell | 1.000 |
| exfiltration | 1.000 |
| secrets | 0.870 |
| network | 0.842 |
| persistence | 0.429 |
| **understated** | **0.359** |
| injection / obfuscation | undefined (every skill labelled the same) |
| overall | 0.868 |

### `PI_DESCRIPTION_MISMATCH` measured

| | precision | recall |
|---|---|---|
| annotator A | 17.6% | 100% |
| annotator B | 35.3% | 100% |
| consensus | 16.7% | 100% |

The rule fires on 17 of 30 sampled skills and the annotators agree it is right on
2–6 of them. And the underlying judgment — "does the skill's description omit or
understate a capability the code has?" — has **κ 0.359**, well below the 0.75
gate. So the rule is not merely imprecise: it is measuring a distinction the
annotators cannot agree on, which is why the line-level GOLD never caught it
(the line-level claim "the matched line exhibits the behaviour" is easy to
agree on; the skill-level claim is not).

**Conclusion:** `PI_DESCRIPTION_MISMATCH` should not be published as a rule with
a precision. Either its claim is narrowed to something annotators agree on, or
it is dropped to a note. Its 7.4% prevalence is not a result.

### The other rules: precision is fine, this recall is not meaningful

`NET_FETCH_CALL`, `NET_HTTP_CLIENT`, `SHELL_EXEC` and `PERSIST_HOOK` score 100%
precision (60% for `NET_FETCH_CALL` under annotator B) — when they fire, the
capability is real. Their category recall (4–33%) is **not** a rule recall: the
category (`network`) is much broader than the rule (`NET_FETCH_CALL` = library
HTTP call), so a skill that reaches the network through `curl` counts as a miss
for a rule that never claimed it. Recall needs a rule-shaped label, not a
category-shaped one, and is left to GOLD-v5.

### Branch breakdown, and the disposition of `PI_DESCRIPTION_MISMATCH`

The rule had four branches. Scoring each against the skill-level labels
(`research/score_skill_gold.py`):

| branch | annotator A | annotator B | both |
|---|---|---|---|
| credentials | 2/4 | 1/4 | 1/4 |
| network | **0/6** | 2/6 | **0/6** |
| running commands | **0/6** | 2/6 | **0/6** |
| high-severity findings | 1/1 | 1/1 | 1/1 |

The network and shell branches are pure false positives on this sample: "the
description does not mention network access" is not a judgeable claim — a skill
that fetches a template is not lying about being a template formatter. Both
branches were **removed** (`SCAN_LOGIC_REVISION` 7). What remains is the
checkable, high-value case: the code reads credentials and the description
mentions neither credentials nor security.

Prevalence fell 10.7% → **6.4%** (585 → 347 of 5442). The rule is still not a
G4-grade signal — the credential branch is 1-2/4 on a 30-skill sample — but it no
longer asserts something annotators cannot agree on.

---

## GOLD-v5: the first table on the current rules

GOLD-v4 measured a rule set that has since changed (rev 7 and rev 8), so the
report's precision column was stale. GOLD-v5 re-labels the current set.

| | |
|---|---|
| items | 250 line-level findings from the current (rev 8) rule set |
| annotators | two independent sessions of `opencode-go/deepseek-v4.1-flash` |
| agreement | 244/250 (97.6%), **Cohen's κ 0.949** |
| disagreements | 6, adjudicated by the annotators' shared instruction |

### What improved

`NET_FETCH_CALL` **100%** (37.5% in GOLD-v1), `NET_HTTP_CLIENT` 87.5% (50%),
`FS_PATH_ESCAPE` 87.5%, `NET_DYNAMIC_URL` 100%, `FS_ABSOLUTE_PATH` 62.5%
(25%), `NET_DOMAIN_LITERAL` 62.5% (12.5%).

### What did not: the prompt-injection rules

`PI_CONCEALMENT`, `PI_EXFIL_INSTRUCTION` and `PI_INJECTION_OVERRIDE` are **0/8
each** — every sampled finding a false positive. The cause is visible in the
corpus: a large share of skills are security *training* material that quotes
injection phrases in order to teach about them (`references/infra-and-supply-chain.md`,
`Data exfiltration patterns`, `Do NOT log ...`). A rule that matches a phrase
cannot tell "the skill does this" from "the skill documents this", and unlike
code rules there is no comment syntax to hide behind. These three are the next
target, and if they cannot be made precise they should become documentation
rather than findings.

### The precision table was frozen (fixed)

`corpus report --gold` computed precision from the gold labels alone and never
checked whether those findings still existed. A rule could go from 8 false
positives to 4 and the table still read 8. `score()` now takes the set of
`(source_id, rule)` pairs present in the findings and drops `tp`/`fp` labels
whose finding is gone; `fn` is always counted, because a miss is supposed to be
absent. Without this, every precision number in this file would be a snapshot of
the rule set at labelling time rather than of the code.

### `PI_*` after the training-material suppression

| rule | prevalence before | after | precision |
|---|---|---|---|
| `PI_CONCEALMENT` | 50 | 29 | 0/4 |
| `PI_INJECTION_OVERRIDE` | 24 | 10 | 0/2 |
| `PI_EXFIL_INSTRUCTION` | 15 | 9 | 0/4 |
| `PI_SYSTEM_IMPERSATION` | 11 | 6 | 1/4 |

The rules do catch real injections (`tests/fixtures/malicious/download-execute`),
but on a random corpus sample they remain low-precision tripwires: the corpus is
mostly security training material that quotes the phrases. If the next GOLD
round cannot lift them above the gate, they should become documentation rather
than findings.

---

## SKILL-v2: rule-shaped labels, so recall is measurable

`SKILL-v1` asked broad categories (`network`, `secrets`). That cannot measure a
rule's recall: the category is wider than the rule, so a skill reaching the
network through `curl` counted as a miss for `NET_FETCH_CALL`, which never
claimed it. `SKILL-v2` asks each **rule's own claim** about the same 30 skills.

| | |
|---|---|
| items | 30 skills × 10 rules = 300 judgments |
| annotators | two independent sessions of `opencode-go/deepseek-v4.1-flash` |
| agreement | 283/300 (94.3%), **Cohen's κ 0.812** |

| rule | precision | recall |
|---|---|---|
| `FS_PATH_ESCAPE` | 100% | 100% |
| `SHELL_EXEC` | 100% | **8.3%** |
| `FS_HOME_ACCESS` | 100% | 22.2% |
| `NET_DOMAIN_LITERAL` | 60.0% | 50.0% |
| `NET_FETCH_CALL` | 25.0% | 50.0% |
| `FS_ABSOLUTE_PATH` | 25.0% | 50.0% |
| `FS_RECURSIVE_WALK` | 0% (2 fp) | — |
| `PERSIST_AGENT_CONFIG` | — | 0% (1 fn) |

### The finding: `SHELL_EXEC` under-detects

On 24 of 30 skills the annotators say an interpreter is invoked; the rule fires
on 2. That is the largest gap measured so far, and it points the opposite way
from every previous pass — the problem there was false positives, here it is
false negatives. The rule's patterns are narrow (specific `subprocess` /
`os.system` / `child_process` shapes) and miss the ordinary case of a script
that simply runs `python3 foo.py` or `bash bar.sh`.

### Caveat: the annotators read the whole skill, some rules read only code

`FS_HOME_ACCESS` and `FS_ABSOLUTE_PATH` deliberately set `docs_confidence: None`
(a `~/` path in a README is not an access). The annotators judged the whole
skill text, docs included, so those recall figures are understated by
construction. Recall for code-only rules needs a code-only worksheet; that is
GOLD-v6 work.

---

## Rule fixes driven by GOLD (v1 → v5)

Every fix below came from a labelled false positive, not from reading code. The
`SCAN_LOGIC_REVISION` counter is bumped so the findings cache is invalidated.

| revision | fix | effect |
|---|---|---|
| 2 | `description_mismatch` admits Chinese and inflected verbs | prevalence down, precision up |
| 3 | a capability declared in `allowed-tools` is admitted | stops duplicating declared-vs-observed |
| 4 | behavioural rules skip comment lines; `OBFUSC_ZERO_WIDTH` needs the zero-width char inside a word | `PERSIST_*`, `FS_HOME_ACCESS`, `NET_HTTP_CLIENT` FPs removed |
| 5 | `NET_DOMAIN_LITERAL` needs URL context for ambiguous TLDs; `PERSIST_*` needs a write; `OBFUSC_HOMOGLYPH` needs a mixed-script word | `NET_DOMAIN_LITERAL` 12.5% → 50%; `OBFUSC_HOMOGLYPH` left the report |
| 6 | trailing comments are comments; `/dev/null` checks the line; `DL_BASE64_BLOB` needs a payload shape; `FS_HOME_ACCESS` is code-only | `FS_ABSOLUTE_PATH` 25% → 50% |
| 7 | `PI_DESCRIPTION_MISMATCH` drops its network and shell branches (0/6 correct) | prevalence 10.7% → 6.4% |
| 8 | test assertions are not behaviour; `-P` needs whitespace; `eval` needs a command | `DL_PASSWORD_ARCHIVE`, `SHELL_EVAL` FPs removed |
| 9–10 | quoted/documentation-shaped lines and attack *discussion* are not `PI_*` instructions | `PI_CONCEALMENT` 50 → 29, `PI_INJECTION_OVERRIDE` 24 → 10 |
| 11–12 | `SHELL_EXEC` widened, then usage text excluded | recall 8.3% → 37.5% |
| 13 | `OBFUSC_ZERO_WIDTH` needs ASCII neighbours; the AWS example key is not a credential; tracking-pixel and cron/path-read tightening | `OBFUSC_ZERO_WIDTH` 33% → 100% |
| 14 | the `PI_*` rules left at 0% are demoted to `Info` | a false `Critical` can no longer fail a gate |
| 15–16 | documentation structure, relative paths, email/DTD, `assert`/usage | `FS_ABSOLUTE_PATH` 62.5% → 75%, `NET_DOMAIN_LITERAL` 62.5% → 71.4% |
| 20 | `DL_UNTRUSTED_DOMAIN` requires network context for a raw IPv4 | a user-agent version (`Chrome/120.0.0.0`) and a dotted version are no longer endpoints |
| 21 | capability derivation and `SECRET_PATH_READ`/`SECRET_ENV_DUMP` skip comment-only lines | a path or host named only in a comment is no longer an observed capability |
| 22 | `NET_DOMAIN_LITERAL` needs host position, not just URL context; a version-shaped token is not a filesystem read | a URL path segment (`…/install.sh`) is not a host; `Chrome/120.0.0.0` is not a read |
| 23 | `DL_REMOTE_INSTALL` needs a fetch on the same line as `chmod +x` | a build script that chmods a `/tmp` file it wrote itself is no longer "installed directly from a URL" |
| 24 | capability derivation does not read a filename as a host, and a shebang is not a filesystem read | `/tmp/build/run.sh` is not an outbound host and `#!/bin/sh` is not a read, so a clean build script is not a declared-vs-observed violation |
| 25 | `PERSIST_AGENT_CONFIG` needs the path to name an agent directory | a skill's own project-local `settings.json` is not agent configuration |
| 26 | `SECRET_GENERIC_ASSIGN` needs the literal to look like a secret *value* | an environment-variable name (`"OPENAI_API_KEY"`) and a placeholder (`"your-token-goes-here"`) are not hardcoded credentials |

Revisions 20 to 26 were reproduced from the false-positive notes above and
carry fixtures (`safe/version-strings`, `suspicious/raw-ip-endpoint`,
`safe/comment-mentions`, `safe/tmp-chmod`, `safe/own-settings`,
`safe/credential-names`), but they are **not re-measured**: the corpus mirror is
not in the repository, so the precision column still reflects rev 8. They await
a GOLD-v6 round, and each should be scored there before any figure is quoted.

### Two structural bugs found on the way

1. **The precision table was frozen.** `corpus report --gold` scored the labels
   alone and never checked whether those findings still existed, so a rule could
   go from 8 false positives to 4 and the table still read 8. `score()` now takes
   the set of live `(source_id, rule)` pairs and drops stale `tp`/`fp` labels.
2. **`corpus index` was ~5 `git` subprocesses per skill.** On a 5,442-skill
   mirror that is ~27,000 spawns and ~13 minutes, all discarded. The enclosing
   repository is now resolved once; index is **24 seconds**.

---

## SKILL-v3: code only, so recall is not confounded by documentation

`SKILL-v2` showed `SHELL_EXEC` at 8.3% recall. But `FS_HOME_ACCESS` and
`FS_ABSOLUTE_PATH` set `docs_confidence: None`, and the annotators read the whole
skill — READMEs included — so their "misses" included paths a README mentions
and the rule deliberately ignores. `SKILL-v3` re-asks the same rule-shaped
questions about the **executable files only**.

| | |
|---|---|
| items | 30 skills × 10 rules, code only |
| agreement | 295/300 (98.3%), **Cohen's κ 0.906** |

| rule | precision | recall | vs. SKILL-v2 (whole skill) |
|---|---|---|---|
| `FS_PATH_ESCAPE` | 100% | 100% | unchanged |
| `SHELL_EXEC` | 63.6–72.7% | **70–80%** | recall was 8.3% before the fix, 37.5% with docs |
| `NET_FETCH_CALL` | 60.0% | 60.0% | 25% / 50% |
| `FS_ABSOLUTE_PATH` | 33.3% | 50.0% | 25% / 50% |
| `NET_DOMAIN_LITERAL` | 33.3% | 40–50% | 60% / 50% |
| `FS_HOME_ACCESS` | 33.3% | 25.0% | 100% / 22% |
| `FS_RECURSIVE_WALK` | 0% (3 fp) | — | 0% (2 fp) |
| `PERSIST_AGENT_CONFIG` | — | 0% (1 fn) | — / 0% |

### What this settles

- **The docs confound was real but small.** Removing it raised `SHELL_EXEC`'s
  recall from 37.5% to ~75% and `FS_HOME_ACCESS` dropped from a tautological 100%
  to 33%, which is the number to trust.
- **Precision falls when the unit is a skill.** `NET_DOMAIN_LITERAL` was 71% at
  the line level and is 33% here: a line-level rater asks "is this line a
  hostname", a skill-level one asks "does this skill contact a host", and the two
  are different questions. Both are reported; neither is the whole truth.
- **`FS_RECURSIVE_WALK` is still 0%** — 3 false positives and no true positives
  on the code-only sample, so its pattern (`rglob`, `rmtree`, `copytree`) is
  matching recursive *deletion* and test helpers rather than a recursive walk.

---

## The regression CI caught (rev 17 → 19)

Four fixture tests were red for a while and the local check did not show it: the
command ended in `| head -3`, which cut the output before `tests/fixtures.rs`
printed. `cargo test --all-targets` reports each suite as it finishes, so the
fixtures suite was past the cut. **CI caught what the local run hid**, and only
because the repository went public and Actions started working again.

Bisect, by running the suite at each commit:

| commit | rev | failing fixtures |
|---|---|---|
| `e7761cc` | 13 | 1 — `hardcoded_keys_are_caught_case_sensitively` |
| `fa42978` | 15 | 4 — the above plus `credential_stealer`, `persistence`, `homoglyphs` |

### What was wrong

`is_documentation_or_quoted` was one function doing two jobs, applied to every
rule in every file:

- **markdown structure** (`#`, `- `, `| `, ```` ``` ````) — correct for a `.md`
  file, wrong in code. It suppressed `#сurl … | bash` in a shell script, where
  the homoglyph exists precisely to survive a crude marker check and where the
  careful `match_in_comment` already does this job — and returns *false* there,
  because after folding the match is no longer in the raw text.
- **quote parity** — correct for a *command* (`'… rm -rf / …'` is a string in a
  test fixture or a user-facing message) and wrong for a *path*, where a quoted
  path is how ordinary code writes one: `cat > "$HOME/.bashrc"`,
  `Path.home() / ".ssh" / "id_rsa"`. It hid a real `PERSIST_SHELL_RC` and a real
  `SECRET_PATH_READ` in two malicious fixtures.

Plus `SECRET_AWS_ACCESS_KEY` skipped `AKIAIOSFODNN7EXAMPLE` unconditionally. That
is right for the doc table it was added for and wrong for a `config.sh` that
assigns it.

### The fix

Two predicates, chosen per rule, plus the file kind:

| predicate | applies to | why |
|---|---|---|
| `is_documentation_structure` + not executable | path and write rules | a quoted path is normal code |
| `is_quoted_example` anywhere | command rules | a command in a literal is prose |
| `!executable && structure` | command rules | markdown is documentation; `#` in code is `match_in_comment`'s job |

| rule | rev17 | rev19 |
|---|---|---|
| `SHELL_DESTRUCTIVE` | P 50% (1 tp, 1 fp) | unchanged |
| `PERSIST_CRON` | P 50% | unchanged |
| `NET_HTTP_CLIENT` | P 85.7% | **87.5%** |
| `PERSIST_AGENT_CONFIG` | P 20% | **25%** |
| `SECRET_PATH_READ` | suppressed out of the table | **P 62.5%, R 100%** |
| fixtures | 4 failing | 22 passing |

The lesson is not "run the tests". It is that **a truncated command is a silent
one**: `| head -3` turned a red suite into a green report.
