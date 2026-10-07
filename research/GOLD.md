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
