# Work: what is open, and what order it goes in

Companion to `docs/STATE.md` (what is true) and `docs/LESSONS.md` (what bit us).
This file is the queue. When something here is done, delete it — a work file that
only grows stops being read.

Last updated at `7c4ed6b`.

## Ready to start, no human needed

### 0. A human labels `research/gold/HUMAN-v1.worksheet.csv`

The cheapest thing on this list and the only one that unblocks the most: 95 rows,
one per rule per skill, ~40 minutes. The tooling landed (`skillguard gold
sample` / `import` / `stats` / `matrix`), `docs/ANNOTATION_GUIDE.md` is written for
someone who has never seen this repository, and the CSV needs no database.

Until it happens, `docs/RULE_QUALITY_MATRIX.md` has every rule at `INFORMATIONAL`
with `recall unknown`, which is the honest state but not a useful one.

Two annotators would also close #11; one gets precision for 36 rules but no κ.

### 1. Narrow the claims of the four `PI_*` rules that still fail G4

The five worst rules fail because their claim is ambiguous, not because the
sample is small. `PI_EXFIL_INSTRUCTION` scores 0/7 and
`PI_INJECTION_OVERRIDE` 1/8 — and both annotators *agree* on those labels, so
more rows will not move them. The claim "an instruction to transmit local data to
an external endpoint" does not say whether `// Send token to your backend` (a code
comment) is one. Narrow the wording until the answer is in the text, then
re-measure.

Size: the wording lives in `message` in `src/scan/rules.rs`, so it is a text-only
change, but it is still a rule change: fixture + `SCAN_LOGIC_REVISION` bump +
regenerated `docs/RULES.md` + a GOLD round. Do **not** expect κ to rise; expect
the precision column to become defensible.

Affected: `PI_EXFIL_INSTRUCTION`, `PI_INJECTION_OVERRIDE`, `PI_CONCEALMENT`,
`PI_SYSTEM_IMPERSONATION`, `SHELL_PRIVILEGE_ESCALATION`, `PERSIST_SHELL_RC`,
`PERSIST_HOOK`.

### 2. Sample size, if and only if after 1

The residual from #10 that is genuinely about `n`: 1–8 labels per rule lets one
finding swing a rule by double digits. `research/build_gold.py --per-rule 25`
produces roughly 900 rows per round. Worth doing **after** the claims are narrow,
because a bigger draw of ambiguous rows buys precision for an ambiguous number.

Cost: ~1 hour of model time per round, two rounds if the adjudication is split.

## Blocked on a person, not on work

| issue | blocked on |
|---|---|
| #1 corpus study | #5 |
| #5 registry permission | a human bumping `vercel-labs/skills#2442` and filing a **fresh** ClawHub request (the old RFC `openclaw/clawhub#3931` was closed by automation as stale) |
| #11 human GOLD | two annotators who did not write the rules, 30–60 minutes each, blind to each other |

Nothing an agent can do moves those three. Saying so is the whole point of this
section.

## Deferred by design

- **#9 `add` / `install` / `update`.** The issue argues its own deferral: a
  package manager for a format with no signing story is a liability, and the
  demand is not demonstrated.

## Known, accepted, not scheduled

- **`PI_*` is `Info`, not `Critical`, on purpose.** A phrase rule cannot tell
  "issues this" from "documents this", and a false `Critical` is worse than no
  finding. Raising the severity needs a semantic model, which this tool
  deliberately does not have.
- **The negation guard was measured and rejected** (κ 0.704, GOLD-v7). An attacker
  could prefix a payload with `not` to silence seven action rules. Reverted, and
  the runbook says do not ship below the gate.
- **`v0.1.2` carries revision 51.** Its cached scans and its behaviour predate the
  parser swap and the line-kind model. Superseded by item 2, not a bug.
