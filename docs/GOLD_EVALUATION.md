# Rule quality evaluation: human GOLD, model silver, fixtures

A rule is a claim about the world, and a false positive is a false accusation.
This document says how a claim's accuracy is measured, and — more importantly —
what each kind of evidence is *not* allowed to prove.

Nothing here calls a model. `skillguard gold export` writes a file; `skillguard
gold import` reads one back. That is the entire integration surface for an
external judge, and it is what keeps the scanner's no-socket invariant intact.

## 1. Three kinds of evidence, never merged

| | stored in | proves | does **not** prove |
|---|---|---|---|
| **Synthetic fixtures** | `tests/fixtures/` | that a rule fires on a known input, and stops firing after a fix | anything about real code: fixtures are written by the same person who wrote the rule |
| **Human GOLD** | `research/gold/*.human.jsonl` | precision, from people who read the evidence | recall, unless the sample was drawn to measure it |
| **Model silver** | `research/gold/silver/*.jsonl` | a cheap second opinion for triage and for phrasing experiments | anything published: two models agreeing is not a human label |

The separation is enforced by types, not by convention. `src/gold.rs` has
`HumanLabel` and `SilverLabel` as distinct structs, and `gold matrix` reads only
`HumanLabel`. A silver file cannot be passed as `--gold` by accident: it is
missing the fields the schema requires, and the parser names the missing one.

**Two model families agreeing is not Human GOLD.** GOLD-v6 published κ 0.845 from
two sessions of one model; a second family scored the same rows at κ 0.723
(GOLD-v8). Every threshold in §6 is defined over *human* labels only, which is
why most rules are `INFORMATIONAL` today.

## 2. The human GOLD schema

One JSON object per line, in `research/gold/HUMAN-vN.jsonl`:

```json
{
  "finding_id": "036279a9529d-125-PI_CONCEALMENT",
  "rule_id": "PI_CONCEALMENT",
  "file": "references/threat-categories.md",
  "line_start": 125,
  "line_end": 125,
  "evidence": "Identifies hidden or obscured text within digital content.",
  "label": "NOT_APPLICABLE",
  "confidence": "HIGH",
  "rationale": "This line documents the category, it does not instruct concealment.",
  "reviewer": "alice",
  "reviewed_at": "2026-11-12"
}
```

| field | rule |
|---|---|
| `finding_id` | derived, never typed by hand: `gold sample` writes it |
| `line_start` / `line_end` | `line_end` defaults to `line_start` when blank |
| `label` | `TP`, `FP`, `AMBIGUOUS`, `NOT_APPLICABLE` |
| `confidence` | `HIGH`, `MEDIUM`, `LOW`; blank is read as `MEDIUM` |
| `rationale` | required in spirit, not enforced: 12 words is enough |
| `reviewer` | **enforced**. A human label with no name is rejected on import |
| `reviewed_at` | ISO date, not parsed — nothing computes on it, and a timezone bug in a provenance field is worse than a string |

`finding_id` is a hash of `source_id + rule_id + file + line`, **not** of the
evidence text. A cosmetic change to normalization would otherwise orphan every
existing human label. `src/gold.rs::finding_id` and
`tests/cli.rs::a_gold_round_trip_needs_a_name` pin both properties.

### Labels that are not TRUE/FALSE

`AMBIGUOUS` and `NOT_APPLICABLE` exist so a reviewer is never forced to guess,
and they mean different things:

- **`AMBIGUOUS`** — the evidence as shown is not enough to decide. Usually a
  truncated line or a variable whose value is set elsewhere.
- **`NOT_APPLICABLE`** — the rule's scope does not cover this finding. The
  canonical case is an action rule matching inside a comment that *documents* the
  action. The rule is not wrong about the text; it is wrong to have applied.

Both are excluded from precision and counted separately. A rule with ten
`AMBIGUOUS` rows has precision `n/a`, which is a different statement from `0%`.

## 3. Model-assisted annotation

The adapter is a file format, not an SDK.

```
skillguard gold sample  …                       # worksheet CSV, label column blank
skillguard gold export  worksheet.csv --format jsonl -o for-judge.jsonl
$JUDGE_DIR/your-judge.sh for-judge.jsonl > judged.jsonl   # any model, any language
skillguard gold import judged.jsonl --silver \
    --model <name> --model-version <version> --prompt-version <hash> \
    --out research/gold/silver/<name>-vN.jsonl
```

Requirements, all enforced or structurally true:

- **No model is a dependency.** There is no API client in this crate; `Cargo.toml`
  has no HTTP dependency and `tests/invariants.rs` fails the build if one appears.
- **No automatic call.** `gold sample` and `gold export` write files and exit.
  Nothing runs a judge unless a person runs it.
- **Prompt version is mandatory.** `--silver` without `--model`,
  `--model-version` and `--prompt-version` is a usage error (exit 3): an
  unversioned opinion cannot be reproduced or withdrawn. GOLD-v9 demonstrated the
  cost of ignoring this — κ moved from 0.593 to 0.779 on identical rows because
  one paragraph of the annotator prompt changed.
- **Silver cannot overwrite human.** Different type, different directory,
  different command flag. `gold matrix --silver` counts the rows and prints the
  count; the precision column never reads them.

Paid APIs are deliberately not wired up. The intended use is a local model or a
free tier used sparingly, and the JSONL in the middle means switching judges is a
file copy rather than a code change.

## 4. The review workflow

```bash
# 1. draw a reproducible sample (same corpus + parameters = same worksheet)
skillguard gold sample \
    --findings research/raw-findings.jsonl \
    --manifest research/corpus-manifest.jsonl \
    --tree research/raw \
    --stratify rule --per-stratum 3 \
    --out research/gold/HUMAN-v1.worksheet.csv

# 2. a reviewer opens it in a spreadsheet and fills `label`, `confidence`,
#    `rationale`, `reviewer`, `reviewed_at`. Leaving a row blank is fine and
#    means "not reviewed yet" — it is skipped on import, not guessed.

# 3. read it back, and look at what you have
skillguard gold import research/gold/HUMAN-v1.worksheet.csv \
    --out research/gold/HUMAN-v1.jsonl
skillguard gold stats research/gold/HUMAN-v1.jsonl

# 4. the matrix
skillguard gold matrix --gold research/gold/HUMAN-v1.jsonl
skillguard gold matrix --gold research/gold/HUMAN-v1.jsonl --format markdown \
    > docs/RULE_QUALITY_MATRIX.md
```

Why a CSV and not a database: a reviewer with 60 minutes uses a spreadsheet, and a
spreadsheet round-trip is a quoting problem, not a schema problem. The header is
fixed (`gold::CSV_HEADER`), comments and evidence with commas and newlines survive
(`csv` crate quoting, pinned by a unit test), and a blank label is skipped.

## 5. Stratified sampling

| `--stratify` | what it does | when |
|---|---|---|
| `rule` (default) | equal rows per rule | a **per-rule** precision table; the rarest rule gets as many rows as the most common |
| `frequency` | uniform over findings, which is proportional to how often each rule fires | "what does a user of this tool actually see", at the cost of leaving rare rules unmeasured |
| `severity` | equal rows per severity | a table organised around blocking risk |

The draw is deterministic: rows are sorted by `sha256(finding_id)` and the first
`n` per stratum are taken, so the same corpus and parameters always produce the
same worksheet. `--per-skill` (default 1) caps repeats: a rule that fires eight
times in one script is one judgement about the rule, not eight votes in its favour.

`PARSE_FAILED`, `PI_DESCRIPTION_MISMATCH`, `LICENSE_*` and `MISMATCH_*` are
excluded from a line-level sample. They report on the skill as a whole and carry
no evidence line, so a line-level row would show the frontmatter `---` and score
the sampler rather than the rule — which is exactly what GOLD-v5 published as a
0/8 before it was caught.

## 6. Thresholds

| tier | requirement |
|---|---|
| **Blocking** | human precision ≥ 0.95 **and** ≥ 30 decided samples |
| **Warning** | human precision ≥ 0.85 **and** ≥ 20 decided samples |
| **Informational** | everything else, including "no human has looked" |

Both conditions must hold. 3/3 is 100% and proves nothing; the sample gate is not
optional, and `gold::status_for` has a unit test for each boundary (29 vs 30,
19 vs 20).

These are **engineering thresholds, not statistical confidence intervals.** The
arithmetic that matters:

| observed | point estimate | 95% Wilson interval |
|---|---|---|
| 29/30 | 96.7% | **[83.3%, 99.4%]** |
| 17/20 | 85.0% | [64.0%, 94.8%] |
| 18/20 | 90.0% | [69.9%, 97.2%] |

So a rule that just scrapes into Blocking at 29/30 still has a lower bound of
83%, i.e. compatible with the Warning tier and well below the 0.95 the label
implies. Treat the tier as **"may this rule block a build"**, never as "how
accurate is this rule". Raising the sample requirement is the only thing that
narrows the interval; raising the precision requirement does not.

A rule may not be promoted on precision alone when its sample is thin, and no
automation promotes anything: the tiers are computed, and a change to a rule is a
code change somebody reviews.

## 7. The matrix

`docs/RULE_QUALITY_MATRIX.md` is generated by `gold matrix --format markdown` and
has a fixed shape:

```
Rule ID | Samples | TP | FP | Ambiguous | N/A | Precision | Recall | Status
```

- **Recall is `unknown` for every rule today**, and that is a measurement fact,
  not missing work. A finding-level sample is drawn *from findings*, so misses are
  absent by construction. Recall needs a skill-level sample ("did this skill
  contain this behaviour at all?"), which is what `research/build_skill_gold.py`
  does — and that is a separate instrument with its own GOLD round.
- **Fixture recall is never corpus recall.** `tests/fixtures/` proves a rule can
  fire; publishing "100% recall" from fixtures would be measuring the test suite
  against itself.
- A rule absent from the table is unmeasured. A rule present with 0 samples has
  been looked at and not judged. Those are different facts and both are shown.

## 8. Versioning and history

Every published matrix records three versions, because a precision number without
them is not citable:

- the **dataset** (`HUMAN-vN.jsonl`) and its row count,
- the **rule set** (`skillguard --version`, `SCAN_LOGIC_REVISION`),
- the **evaluation date**.

Rules:

- A human label is never overwritten by a model result, and never edited in place.
  A re-review creates `HUMAN-vN+1` and the old file stays.
- A GOLD round that fails its gate is kept with its own section rather than
  deleted (`research/GOLD.md`: GOLD-v7 κ 0.704, GOLD-v9 κ 0.593). A surviving
  number whose failed attempts were deleted is a lie of omission.
- `gold import` refuses to write a human label with no `reviewer`. That is the one
  provenance check available offline, so it is enforced.

## 9. What this does not do

- It does not judge evidence quality, only counts labels.
- It does not reconcile two reviewers. Two independent human label sets and a κ is
  `skillguard corpus agreement`'s job, and the runbook is `research/GOLD.md`.
- It does not measure the scanner's *core rules*; the rules are untouched by this
  work, by design.
- It does not solve issue #11. It makes the human round cheap enough to actually
  happen: one CSV, 95 rows at `--per-stratum 3`, about 40 minutes.
