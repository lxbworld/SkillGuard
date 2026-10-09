Thanks. A few things that make this reviewable.

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets` and `cargo deny check` are all green, and I read the whole test output (not `| head`).
- [ ] No new network dependency in the scanner, no new `unsafe`, no process spawn outside `src/hash.rs`. See `CONTRIBUTING.md`.
- [ ] If a rule changed: a fixture that would have caught the old behaviour, and `SCAN_LOGIC_REVISION` bumped in `src/scan/rules.rs`.
- [ ] If a rule changed: `docs/RULES.md` regenerated.
- [ ] All text is in English.

## Evidence

<!-- For a rule fix, the before/after precision and recall, and where the numbers came from.
     For a bug, the command you ran and the output. "It works now" is not evidence. -->

## Does this need a data source?

<!-- If this touches research/, say which layer and whether that registry has been contacted.
     See research/DISCLOSURE.md. Absence of a prohibition is not permission. -->
