# Lessons: mistakes made here, so they are not repeated

Each entry is a real error in this repository, what it cost, and the check that
now prevents it. If an entry has no check, it is not a lesson yet — it is a wish.

## Measuring my own instrument

**The annotator instruction moved κ more than the rules did.** GOLD-v9 scored
κ 0.593; GOLD-v10 scored κ 0.779 on the *same rows* with the *same two models*.
The only change was one paragraph saying that a `SKILL.md` body is the instruction
an agent follows. 24 of 38 disagreements were that one unstated sentence.

Check: `research/GOLD.md` records every round with the instruction it used.
Breaks for a would-be round: a κ with no statement of what the annotator was told.

**A same-model κ is a test–retest figure, not agreement.** GOLD-v6 published
κ 0.845 from two sessions of one model. Re-labelling the same rows with a second
family gave 0.723, below the project's own gate.

Check: GOLD rounds use two model families now, and every published κ says which
families and how many humans (none, so far).

**A sampler defect was published as a rule result.** GOLD-v5 sampled
`PARSE_FAILED` and `PI_DESCRIPTION_MISMATCH` even though they carry no evidence
line, so they were judged on line 1 (the frontmatter `---`) and scored 0/8. That
measured the sampler, not the rule.

Check: `SKILL_LEVEL_RULES` excludes them from the worksheet.

## Line kinds and suppressions

**Recognising a docstring *opener* misreads its *closer*.** The first
implementation looked for a bare line or a `def` before `"""`. `""".strip()`
ending a data block has an empty prefix, so it looked like an opener, every
following line became "documentation", and a real `NET_DYNAMIC_URL` finding fifty
lines later was silently suppressed.

Check: quote parity in `src/text.rs::classify_lines`, plus
`tests/fixtures/malicious/docstring-then-code`, which fails if the call after a
docstring stops being reported.

**Suppressing in the wrong direction is invisible without a before/after.**
`safe/docstring-usage` reported 7 findings before the change and 0 after; without
running the old binary first, "0 findings" looks like success either way.

Check: every suppression change is measured by re-scanning the whole corpus and
diffing the rule counts, and by re-scoring an existing GOLD set to confirm the
suppressed rows were false positives. In this case 7 of 7 were.

**A crude check can beat a careful one.** Applying both `is_documentation_structure`
and `match_in_comment` let the crude one win and three malicious fixtures stopped
being caught. A rev15 regression CI found it.

## Numbers and documentation

**A logic change without a revision bump serves stale cache.** The corpus cache is
keyed by the rules fingerprint, and it does not include the parser or the line
classifier. Revision 52 (parser) and 53 (line kinds) both needed a bump; the
comment in `src/scan/rules.rs` says who forgot and what it froze.

**Documentation drifted from the code, and nothing noticed.** `docs/THREAT_MODEL.md`
named 7 rule ids that had never existed, omitted 18 of the 55 real rules, and gave
6 wrong severities. It was fixed in #15 and is now enforced by
`tests/invariants.rs::the_threat_model_names_real_rules_with_their_real_severity`,
verified by breaking it in all three directions.

**A header claimed 13 of 36 rules passed while the table below it said 16.** Found
while writing `docs/STATE.md`, four commits after the number changed. Nothing
checks prose against tables.

**A test passed locally and produced an empty result on CI.** The gold round-trip
test sampled from `research/raw-findings.jsonl`, and `research/raw/` is gitignored,
so on CI the worksheet contained only a header. It asserted `lines[1]`, which
panicked rather than quietly passing — but the lesson is the design: a test must
build its own fixture, not borrow the corpus. It now samples a three-file tree it
creates itself.

**A blank CSV tail is already one empty field per column.** Filling a worksheet by
appending `TP,HIGH,…` added a twelfth field to an eleven-field row, because the
blank tail `,,,,,` ends with a comma. `gold import` read the label as empty, skipped
every row, and the matrix printed nothing — a silent no-op. The test now replaces
the tail rather than appending, which is also what a spreadsheet does.

**A commit message carried an invented number.** The same commit that added the
entry above stated `PI_DESCRIPTION_MISMATCH` was "7.6% of declared skills"; the
measured value is 54.9% of the 386 declaring skills (3.9% of all 5,442), and it
was never in `docs/STATE.md` at all — I recalled it instead of reading it.
`cbfc36f` cannot be rewritten, so the correct figure is in `docs/STATE.md` and
this entry is the record. The habit that prevents it: every number written into a
commit message or a summary is copied from a command's output in the same
session, never from memory.

Lesson: the generated table is the source of truth; prose that repeats a number
is a copy, and copies drift. Prefer "see the table below".

**`cargo deny` was claimed clean in the README while it was failing.** True when
written, false 20 commits later. Now corrected, and CI has a `cargo-deny` job.

**A bad rule id was in the code, not just the docs.** `PI_SYSTEM_IMPERSATION`
survived because nothing compared the catalogue to the documentation. Fixed in
#15 with no alias: the measured population was one release, 10 downloads, 0
stars, so no third-party policy file could name it.

## Verification habits

**`| head` on `cargo test` hid four failing fixture suites.** One result line is
printed per binary, so the first line can be a passing one.

Check: `cargo test --all-targets` is read in full, and CI runs it.

**A test that passes on both versions proves nothing.** The first piped-installer
regression test ran from the repository root, where the broken `install.sh` found
`./action/install.sh` by accident. It was changed to run from an unrelated
working directory, and then verified to fail on the old script.

**Green tests do not prove the user-visible thing.** The documented
`curl … | bash` one-liner was broken for every first-time user while the suite was
green, because no test ever piped the script. It is now covered by a distribution
test with `HOME` redirected.

**A fixture with a credential gets the push rejected.** GitHub push protection
blocked a realistic Slack token in a fixture; the fixture was changed to use a
command instead. Use commands, not credentials, as probe payloads.

**Service start/stop is never the agent's call.** A "restart the API" once deleted
three containers because the stop script did more than its name. Read every
script before running it, and tell the user what needs restarting instead.

## Writing about failures

**A failed round is more valuable than a deleted one.** GOLD-v7 (κ 0.704) and
GOLD-v9 (κ 0.593) were both kept as committed label files with their own sections
in `research/GOLD.md`. Deleting them would have made the surviving number look
like the first attempt, which is a lie of omission.

**Do not choose the flattering reading of an ambiguity.** When a κ misses the
gate, the honest write-up lists the readings and does not pick the one that
exonerates the code. That is why `research/GOLD.md` says the sample may be too
small *and* the claims may be unreproducible, without choosing.
