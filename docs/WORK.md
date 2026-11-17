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

## Ready to start, no human needed

Nothing. The queue below this line is either done or blocked on a person.

One open question a future round should settle first: at ~92% raw agreement,
the κ gate is prevalence-fragile (GOLD-v17 0.770 vs GOLD-v18 0.718 on
same-sized draws from adjacent revisions). A future GOLD round should state its
draw composition (per-rule n, rows in known-boundary families) alongside the
gate, or the boundary families (`PI_CONCEALMENT`, `OBFUSC_TRACKING_PIXEL`
specimens, quoted-path specimens) need a fixture-settled definition.

### Done since `7c4ed6b`

- **`PI_*` grammar suppression (rev 57).** Narrowing the claims (rev 56) fixed
  agreement, not precision; the suppression now covers the shapes: quoted
  specimens (located case-insensitively), `//` comments in example code,
  prompt-format fragments, technique-enumeration labels, and three pattern
  narrowings (`without consent`, `do not log secrets`, bare `upload
  credentials`).
- **Suppression sees the whole line (rev 57).** `raw` was the 200-character
  display cap while the regexes ran on the full haystack — the same defect the
  rev 50 evidence bug had on the display side, and it cut both ways.
- **The sample-size round (rev 58–60, GOLD-v14 … v17).** `--per-rule 25`
  exposed what 8-row draws hid; two guide fixes and three scanner sweeps came
  out of it; two failed rounds (v14 0.723, v16 0.556) are kept as the record.
  `SHELL_EXEC` measured 14/25 and its own `subprocess.…` branch was
  name-not-call; `FS_ABSOLUTE_PATH` now says "referenced" (its old
  "accessed" cost twelve annotator disagreements); `.top` is a JavaScript
  property as often as a TLD; compliance guidance that flags copyleft licences
  names them in order to review them.

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
