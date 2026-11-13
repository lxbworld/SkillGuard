# State: what is true right now

Verified by running it, not by memory. Last checked at `7c4ed6b`.
When this file and the code disagree, the code wins and this file is the bug.

Numbers are only citable together with the revision they were measured at. A
number in this file without a revision is a number nobody should quote.

## The build

| | |
|---|---|
| branch | `main`, level with `origin/main` |
| version | `0.1.2` (crate + `RULE_SET_VERSION`) |
| `SCAN_LOGIC_REVISION` | **54** |
| rules | 55 |
| tests | 357 pass, 0 fail (`cargo test --all-targets`) |
| clippy / fmt | `-D warnings` clean / clean |
| `cargo deny` | advisories, bans, licenses, sources all ok, `ignore = []` |
| CI | green on `7c4ed6b` (linux, windows, cargo-deny, Action self-test) |
| tag | `v0.1.2` = `130c41e`, 10 release assets |

`v0.1.2` was cut at revision **51**. Revisions 52 (parser swap), 53 (line kinds)
and 54 (name versus call) are on `main` and in no release. `v0.1.3` carries them.

## The corpus (revision 53)

`research/raw-findings.jsonl`, 5,442 skills, reproduced byte for byte from a cold
cache. `docs/CORPUS_REPORT.md` regenerates identically from it.

| | |
|---|---|
| skills scanned | 5,442 |
| declare permissions | 386 (7.1%) |
| findings | 8,732 |
| `MISMATCH_UNDER_DECLARED` | 76 of 386 declared (19.7%) |
| `PI_DESCRIPTION_MISMATCH` | 212 of 5,442 (3.9%), i.e. 54.9% of declared |
| `PARSE_FAILED` | 76 (1.4%) |
| top rule | `LICENSE_MISSING` 1,148 skills (21.1%) |

## The precision table (GOLD-v11)

199 rows, 36 rules, κ **0.757** over two different model families
(`deepseek-v4.1-flash` vs `z-ai/glm-5.3-flash`), 21 disagreements adjudicated.
**18 of 36 rules pass G4** (precision ≥ 0.85), 13 of them at 100%.

Not a human GOLD set. `research/PROTOCOL.md` G3 asks for two humans; no human has
ever labelled anything here (issue #11).

## Rule quality evaluation

`skillguard gold sample | export | import | stats | matrix`, plus `src/gold.rs`.
Three kinds of evidence, separated by type rather than convention:

| | where | feeds the published precision |
|---|---|---|
| synthetic fixtures | `tests/fixtures/` | never |
| human GOLD | `research/gold/HUMAN-vN.jsonl` | only this |
| model silver | `research/gold/silver/` | never; counted and printed |

Current human state: **zero labels**. `research/gold/HUMAN-v1.worksheet.csv` holds
95 rows awaiting a reviewer, and `docs/RULE_QUALITY_MATRIX.md` therefore lists all
55 rules as `INFORMATIONAL` with `recall unknown`. That is accurate, not
unfinished: the `GOLD-v1`..`GOLD-v10` sets in `research/gold/` are model labels.

## What each thing is measured to be

- **Docstring and block-comment lines are documentation; Markdown is not.**
  Two model families independently rate findings on docstring lines 7% and 14%
  true, against 72% and 73% on executable code. A `SKILL.md` body is the
  instruction an agent follows, so a command there is behaviour — fenced blocks
  score 48%, no better than prose, and the `remote-install` fixture needs them.
- **Two sessions of one model are not independent.** The same 209 rows gave
  κ 0.845 same-model and κ 0.723 across families.
- **The annotator instruction can move κ more than the rules do.** GOLD-v9
  scored 0.593 and GOLD-v10 scored 0.779 on identical rows and identical models;
  the only change was one paragraph saying what a `SKILL.md` body is.
- **`cargo deny` is clean** because `serde_yaml` (and `unsafe-libyaml` behind it)
  is gone, replaced by `serde-saphyr`. The measured cost is `PARSE_FAILED`
  71 → 76; the declaration rate did not move.

## Pinned by a test

Do not break these; `tests/invariants.rs` and the fixture suite fail the build.

- No socket in the scanner. No HTTP-client dependency. Collection is Python in
  `research/`, by design.
- Only `src/hash.rs` spawns a process (`git`). No `unsafe`. No telemetry.
- `docs/RULES.md` is generated and must match `skillguard rules --format markdown`.
- `docs/THREAT_MODEL.md` names real rule ids with their real severities.
- Every finding carries file + line + evidence, and the evidence contains the
  match it reports.
- The installer never installs an unverified binary; a checksum mismatch is not a
  fallback case, it is a refusal.
- Two fixture pairs pin the line-kind model in both directions:
  `safe/docstring-usage` (7 findings before, 0 after) and
  `malicious/docstring-then-code` (the call after a docstring must still fire).
