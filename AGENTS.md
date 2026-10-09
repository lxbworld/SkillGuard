# Notes for AI agents working on SkillGuard

`CONTRIBUTING.md` is the human-facing version of this file. Read it too.

## Language

Everything committed or posted here is **English**: commit messages, issues,
pull requests, review comments, docs, code comments, release notes. The
repository is public and reviewed by people who do not share a first language.

## Do not break these

`tests/invariants.rs` enforces them and will fail the build:

- The scanner never opens a socket. No HTTP client, and no dependency that
  brings one in. Data collection lives in `research/` as Python, on purpose.
- Only `src/hash.rs` spawns a process (`git`). Nothing else.
- No `unsafe`.
- `docs/RULES.md` is generated and must match the code.
- No telemetry dependency.

## Changing a rule

A rule is a claim about the world, and a false positive is a false accusation.

1. Add or update a fixture under `tests/fixtures/` that would have caught the old
   behaviour.
2. Bump `SCAN_LOGIC_REVISION` in `src/scan/rules.rs`. The scan cache is keyed by
   the rule fingerprint; a logic change without a bump leaves stale results, and
   it silently froze the precision table once already.
3. Regenerate `docs/RULES.md`.
4. Re-measure. `research/GOLD.md` is the runbook; `corpus report --gold` prints
   the precision table.

## Verify, do not assume

- **Run the whole test output.** `cargo test --all-targets` prints one result line
  per binary, so `| head` can hide an entire failing suite. It hid four failing
  fixtures in this repository until CI caught them.
- A green unit test does not prove user-visible behaviour. Reproduce the real
  thing before claiming a fix.

## Research and disclosure

`research/` is the study's method, and its rules are not negotiable: no payloads
are ever published; a registry is contacted before any prevalence figure for it
is published ("absence of a prohibition is not permission"); findings go to the
operator privately first, with a 7-day window. The state of each request is in
`research/DISCLOSURE.md`.

Collectors require an explicit `--i-have-permission` flag and exit non-zero
without it. Do not remove that gate.
