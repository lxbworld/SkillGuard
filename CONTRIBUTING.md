# Contributing to SkillGuard

Thanks for looking. This project is a security tool, so the bar is a little
higher than "the tests pass": a claim about what a skill does has to be
reproducible by someone who does not trust us.

## Language

**Everything in this repository is written in English** — issues, pull
requests, commit messages, code comments, documentation, and release notes. The
project is public and meant to be used and reviewed by people who do not share
a first language, so English is the working language throughout.

## Getting set up

```bash
git clone https://github.com/lxbworld/SkillGuard
cd SkillGuard
cargo build --release
cargo test --all-targets
```

Rust 1.78 or newer. The binary has no runtime dependencies and no network
access; scanning is offline by design.

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo deny check
```

All four are green on `main`, and CI runs them on every push. Two notes:

- **Run the whole test output.** `cargo test --all-targets` prints one line per
  test binary, so piping it through `head` can hide a failing suite — that has
  happened here, and it hid four failing fixtures for a while.
- CI runs Linux on every push, and Windows and macOS on release tags and
  weekly, to keep the Actions minutes spent on the commits that need them.

## The invariants

These are enforced by `tests/invariants.rs`, not by convention. A change that
breaks one of them will fail CI, and it is not a bug in the test:

| Invariant | Why |
|---|---|
| The binary never opens a socket | The scanner must be honest about being offline. There is no HTTP client in `Cargo.toml`, and no dependency that brings one in. |
| Only `src/hash.rs` spawns a process | `git` is the one external tool the digest needs. Everything else is pure Rust. |
| No `unsafe` anywhere | There is no reason for it, and it makes the "deterministic" claim harder to defend. |
| `docs/RULES.md` matches the code | The rule reference is generated; drift means a reader is being told something false. |
| No telemetry dependency | "No telemetry" is a promise, and promises that are not tested are marketing. |

Collection lives in `research/` on purpose, as Python. The scanner itself never
grows a network dependency to make data collection convenient.

## Changing a rule

Rule changes are the most delicate kind, because a rule is a claim about the
world and a false positive is a false accusation.

1. **Say what the rule claims, and what it does not.** A rule whose message
   overstates its evidence is a bug even when it matches correctly.
2. **Add or update a fixture** under `tests/fixtures/`. The malicious fixtures
   are the regression net, and they have caught real regressions that a unit
   test did not.
3. **Bump `SCAN_LOGIC_REVISION`** in `src/scan/rules.rs`. The scan cache is keyed
   by the rule fingerprint, so a logic change that does not bump it leaves stale
   results behind — including in the precision table, which silently stayed
   frozen once because of exactly this.
4. **Re-measure.** A rule change without a re-run is an unverified claim.

The full loop, and the history of which round changed what, is in
`research/GOLD.md`.

## Tests

| Suite | What it covers |
|---|---|
| `tests/fixtures.rs` | End-to-end behaviour on whole skills, malicious and safe |
| `tests/invariants.rs` | The architectural promises above |
| `tests/corpus.rs` | The corpus pipeline is deterministic and reproducible |
| `tests/cli.rs` | The command-line surface |
| `tests/distribution.rs` | The Action, the installer and the pre-commit hook |

The suites above are the whole test surface. A new rule should come with a
fixture; a new behaviour on an existing rule should come with the fixture that
would have caught it.

## Research and disclosure

`research/` is not just tooling, it is the study's method, and it has rules that
are not negotiable:

- **No payloads are ever published.** Reports carry a rule id, a content digest,
  a path and a line. A malware corpus is a distribution mechanism.
- **A registry is contacted before any prevalence figure for it is published.**
  Absence of a prohibition is not permission. The state of each request is
  recorded in `research/DISCLOSURE.md`.
- **Findings are reported privately first**, with a 7-day window before anything
  is public.
- **Full 40-hex commits only.** A corpus pinned to a branch is not reproducible,
  and an unreproducible security measurement is not worth publishing.

If you are adding a data source, read `research/PROTOCOL.md` and
`research/TERMS-REVIEW.md` first.

## Reporting a security issue

SkillGuard itself is a security tool, so it has an obvious attack surface: the
parsers, the digest, and the policy engine. Please do not open a public issue
for a vulnerability in SkillGuard. Use GitHub's private vulnerability reporting
on the Security tab, and give us a chance to fix it before it is public.

This is separate from findings *about a skill*, which are the point of the tool
and belong in a normal issue (with the payload omitted — see above).

## Scope

Things this project deliberately does not do, so a PR adding them will likely be
declined: a web registry, a SaaS, an agent runtime, an autonomous security
agent, enterprise MDM, a self-trained model, or scanning the MCP ecosystem.
`docs/VIABILITY.md` explains the reasoning; the short version is that the
project is a verification layer, not a package manager, and `add`/`install` are
deferred until there is demonstrated demand.
