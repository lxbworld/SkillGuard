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

### 1. Suppress the `PI_*` discussion grammar, not just its vocabulary

Narrowing the claims (rev 56) raised annotator agreement from 0.762 to 0.780 and
left precision exactly where it was. `PI_INJECTION_OVERRIDE` is 0/8 with both
annotators in **exact agreement**: they are not confused about the claim, the
detector fires on the wrong shape.

`discusses_the_attack` matches words ("injection", "jailbreak", "payloads that
override") and misses the shapes a writeup about attacks uses: a markdown table of
categories, a reference document enumerating payloads, a `.yaml` of system prompts
*to detect*. That is a suppression change in the same family as revisions 54 and
55 — fixture first, then measure that no true positive is lost.

Affected: `PI_INJECTION_OVERRIDE`, `PI_SYSTEM_IMPERSONATION`, `PI_CONCEALMENT`,
`PI_EXFIL_INSTRUCTION`. Do not expect a wording change to help; it was tried.

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
