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
