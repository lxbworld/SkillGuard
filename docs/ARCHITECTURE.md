# SkillGuard — Architecture

Stack: **Rust (edition 2021, MSRV 1.78)**, one binary, no runtime dependencies.
This document describes the architecture and the interface boundaries. It contains
no implementation code.

> **Implementation status (2026-10-07, non-normative).** This document was written
> before the implementation, so the real module layout is flatter than the tree
> below (for example `src/models.rs`, `src/scan/mod.rs`, `src/scan/rules.rs`,
> `src/hash.rs`, `src/policy.rs`, `src/permissions.rs`, `src/corpus.rs`), and the
> Phase 4 `add`/`install` modules (`install/`, `diff/`, `provenance/`) are **not
> implemented, deferred by design** (issue #9). **What is actually binding is the
> invariants and boundaries in this document** (end of §2, §3, §4); each one is
> enforced by a test (see `tests/invariants.rs`). The Phase 0 batch driver is
> implemented as `src/corpus.rs`, which was not planned in any module here.

---

## 1. Why Rust (against the Python recommendation in the requirements, §18)

The requirements originally recommended Python (Typer/Pydantic/PyYAML/Rich). The
reasons for Rust instead:

| Dimension | Rationale |
|---|---|
| **Single-binary distribution** | No Node or Python runtime in CI / a pre-commit hook / a GitHub Action. A security tool has to run on any machine, or it gets bypassed. |
| **Zero-dependency supply chain** | This project *is* a supply-chain security tool. A large dependency tree of its own (tree-sitter grammars + LLM SDKs) would be ironic and dangerous. Rust dependencies are few and auditable. |
| **Deterministic and reproducible** | No GC, no dynamic loading, no implicit time or randomness. Lockfile hashes stay stable. |
| **Performance for a long-lived installer** | Recursive scanning plus SHA-256 over large directories; `sha2` + rayon is enough (the MVP is single-threaded + `walkdir`). |
| **Maintainable by DeepSeek** | The requirement was "a single model can complete the development". Rust's compile-time type checking plus clippy surface AI-generated mistakes earlier. |

The cost: Rust bindings for tree-sitter are less mature than Python's, and MFA /
interactive TUIs are more expensive. **Mitigation**: the MVP does not depend on
tree-sitter (see §5).

---

## 2. Crate structure

One crate with clear module boundaries (a lib + bin dual entry point). No
premature workspace split.

```
skillguard/
├─ Cargo.toml
├─ LICENSE                      # Apache-2.0
├─ NOTICE
├─ README.md
├─ src/
│  ├─ lib.rs                    # Stable public API (for embedding in other Rust tools)
│  ├─ main.rs                   # CLI entry point (clap)
│  ├─ models/                   # Pure data types, zero dependencies, serde
│  │  ├─ mod.rs
│  │  ├─ skill.rs               # SkillManifest, SkillDocument, Frontmatter
│  │  ├─ capability.rs          # Capability, CapabilitySet, PermissionDecl
│  │  ├─ finding.rs             # Finding, Severity, Confidence, Evidence
│  │  ├─ policy.rs              # Policy, PolicyDecision, Violation
│  │  ├─ provenance.rs          # Provenance, SourceRef
│  │  ├─ lockfile.rs            # SkillGuardLock
│  │  └─ report.rs              # ScanReport / ScanSummary
│  │
│  ├─ parser/                   # SKILL.md → SkillDocument
│  │  ├─ mod.rs                 # frontmatter splitting (byte-level, no assumption about which line the YAML starts on)
│  │  ├─ frontmatter.rs         # serde_yaml subset, safe deserialization
│  │  ├─ markdown.rs            # code fence extraction / line-number mapping
│  │  └─ references.rs          # resolve references inside references/ assets/ scripts/
│  │
│  ├─ scan/                     # The only way in for UNTRUSTED INPUT
│  │  ├─ mod.rs                 # ScanEngine: orchestrates every rule
│  │  ├─ rule.rs                # trait Rule + RuleContext + the contract
│  │  ├─ walk.rs                # safe directory traversal (symlink / depth / size limits)
│  │  ├─ text.rs                # normalization: Unicode NFKC, hidden characters, base64 candidate extraction
│  │  ├─ rules/
│  │  │  ├─ mod.rs
│  │  │  ├─ secrets.rs          # the SECRET_* rules
│  │  │  ├─ shell.rs            # the SHELL_* rules
│  │  │  ├─ network.rs          # the NET_* rules
│  │  │  ├─ filesystem.rs       # the FS_* rules
│  │  │  ├─ download.rs         # the DL_* rules (including the download→execute chain)
│  │  │  └─ injection.rs        # the PI_* rules (deterministic heuristics)
│  │  └─ dependency.rs          # package.json / requirements.txt / pyproject parsing
│  │
│  ├─ capability/               # deriving observed capabilities
│  │  ├─ mod.rs
│  │  ├─ derive.rs              # findings → CapabilitySet
│  │  └─ declared.rs            # read PermissionDecl from the permissions field
│  │
│  ├─ diff/                     # ⭐ the differentiation core
│  │  └─ mod.rs                 # declared_vs_observed() → a list of Mismatch
│  │
│  ├─ policy/
│  │  ├─ mod.rs
│  │  ├─ schema.rs              # SKILLGUARD.policy.yaml parsing
│  │  └─ engine.rs              # policy evaluation, produces a PolicyDecision
│  │
│  ├─ hash/                     # content addressing
│  │  └─ mod.rs                 # merkle-ish directory hash (canonical serialization)
│  │
│  ├─ provenance/
│  │  ├─ mod.rs
│  │  └─ git.rs                 # git metadata (subprocess, not libgit2 — an MVP trade-off)
│  │
│  ├─ lockfile/
│  │  ├─ mod.rs
│  │  ├─ schema.rs              # SKILLGUARD.lock v1
│  │  └─ migrate.rs             # skills-lock.json → SKILLGUARD.lock (interoperability)
│  │
│  ├─ install/
│  │  ├─ mod.rs                 # add/install/update orchestration
│  │  ├─ source.rs              # source spec parsing (github:/path:/git/url)
│  │  ├─ agents.rs              # agent directory registry (.claude/.cursor/.agents/...)
│  │  └─ approve.rs             # recording approvals
│  │
│  └─ report/
│     ├─ mod.rs
│     ├─ text.rs                # human-readable (table + evidence lines)
│     ├─ json.rs
│     ├─ sarif.rs               # SARIF 2.1.0 (GitHub Code Scanning)
│     └─ markdown.rs            # PR comments
│
├─ tests/
│  ├─ fixtures/
│  │  ├─ safe/                  # must produce zero findings
│  │  ├─ malicious/             # must trip the named rule
│  │  ├─ suspicious/            # must produce evidence without raising severity
│  │  ├─ obfuscated/            # base64 / Unicode obfuscation
│  │  └─ edge_cases/            # empty files, oversized files, symlink loops, binary
│  ├─ parser_tests.rs
│  ├─ scan_rules_tests.rs       # one regression test per rule (requirements §21.10)
│  ├─ diff_tests.rs
│  ├─ policy_tests.rs
│  ├─ lockfile_tests.rs
│  └─ golden/                   # output snapshots
└─ docs/
```

**Key boundary constraints (enforced at the architecture level)**:
- `models/` and `hash/` **must not depend on any other internal module**. They are
  the contract layer.
- `scan/` **must not** depend on `install/`. This prevents "the scanner loosens its
  judgement in order to install".
- Inside `scan/`, `std::process::Command` is **forbidden** (except in
  `provenance::git`), as is `std::net`. Enforced in CI with `#![forbid]` / clippy
  lints.

---

## 3. Dependency policy (minimal)

| Purpose | crate | Note |
|---|---|---|
| CLI | `clap` (derive) | |
| Serialization | `serde`, `serde_json` | |
| YAML | `serde_yaml` (switch to `serde_norway` or `saphyr` if the deprecation warning lands) | frontmatter / policy |
| TOML | `toml` | pyproject parsing |
| Regex | `regex` | no backtracking, linear time, ReDoS-safe |
| SHA256 | `sha2` | |
| Directory traversal | `walkdir` | with `follow_links(false)` |
| glob | `globset` | |
| Path normalization | `path-clean`, `path-slash` | handles `..` / Windows separators |
| Colored output | `owo-colors` / `anstream` | disabled automatically when not a TTY |
| Errors | `thiserror`, `anyhow` (bin only) | |

**Forbidden dependencies**: any LLM SDK, any HTTP client (except for the Phase 4
Git-source install), any telemetry crate.

CI runs `cargo deny`: it rejects `unsafe` code (`#![forbid(unsafe_code)]`) and
rejects extra sources.

---

## 4. Core data flow

```
                        ┌──────────────────────┐
                        │  UNTRUSTED INPUT     │
                        │  SKILL.md scripts/   │
                        │  package.json URLs   │
                        └──────────┬───────────┘
                                   │  parser::parse  (byte-safe, bounded)
                                   ▼
                        ┌──────────────────────┐
                        │   SkillDocument      │  read-only data
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
      ┌───────────────┐   ┌────────────────┐   ┌──────────────────┐
      │ ScanEngine    │   │ declared perms │   │ dependencies     │
      │ → Vec<Finding>│   │ (frontmatter)  │   │ (lockfile-free)  │
      └───────┬───────┘   └────────┬───────┘   └────────┬─────────┘
              │                     │                    │
              ▼                     │                    │
      ┌───────────────┐             │                    │
      │ CapabilitySet │◄────────────┴────────────────────┘
      │  (observed)   │        derive() + dependency analysis
      └───────┬───────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ diff::declared_vs_observed()          │  ⭐ the differentiation core
      └───────┬───────────────────────────────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ policy::evaluate(SkillDocument,       │
      │                  CapabilitySet,       │
      │                  Mismatch)            │
      └───────┬───────────────────────────────┘
              │
              ▼
      ┌───────────────────────────────────────┐
      │ PolicyDecision                        │
      │  allow | warn | require_approval|deny │
      └───────┬───────────────────────────────┘
              │
      ┌───────┴────────┬─────────────┬──────────────┐
      ▼                ▼             ▼              ▼
  report::render  install::add   hash::dir_hash  provenance::collect
  (text/json/     (blocked on deny)              (source+commit+digest)
   sarif/md)            │
                         ▼
                 SKILLGUARD.lock  →  install::install(agent dirs)
```

**Invariants**:
- I1: Under a `deny` decision, no file may be written into an agent directory.
- I2: The `permissions` field written into `SKILLGUARD.lock` must come from
  `declared`, and `observed` must come from the scan; the two are never mixed.
- I3: `content_digest` must be computed by **canonical serialization**, so the same
  content yields the same result on any machine.
  (Specified in requirements §23, "reproducible install".)

---

## 5. Scanner design

### 5.1 The rule contract

```rust
pub trait Rule {
    fn id(&self) -> RuleId;                    // "SECRET_PRIVATE_KEY"
    fn default_severity(&self) -> Severity;
    fn applies_to(&self, kind: ArtifactKind) -> bool;   // Frontmatter / Markdown / Script / Manifest
    fn scan(&self, ctx: &RuleContext) -> Vec<Finding>;
}
```
`RuleContext` provides: the normalized text, the **original** text, a line-offset
map, and the already-extracted set of URLs/domains/shell tokens (shared across
rules so it is computed once).

### 5.2 Why the MVP does not use tree-sitter

A regex plus YAML/JSON parsers already covers every deterministic check in
requirements §8. tree-sitter has exactly one place where it would genuinely earn
its keep here: **cross-statement download→execute dataflow analysis in
Python/JS/shell** (combinations like `curl ... | sh`).

**Decision**: the MVP detects chains with a "same line + adjacent line" window
join. If that is not precise enough, at the end of Phase 1 we introduce
`tree-sitter-bash` / `tree-sitter-python` for the `scripts/` directory only
(feature-gated), used exclusively by the `DL_CHAIN_*` rules, with no effect on any
other rule.

### 5.3 The normalization pipeline (against obfuscation)

Every text rule operates on the **normalized view**, while evidence keeps the
original bytes:

1. Unicode NFKC normalization
2. Strip zero-width characters (U+200B–200D, U+FEFF, U+00AD, the various variation selectors)
3. Homoglyph marking: non-ASCII that looks like ASCII → record `obfuscation_suspected`
4. Base64 candidates: length ≥ 24 with a legal character set → produce **shadow text**
   for the injection rules to scan, while also keeping the `DL_BASE64_BLOB` finding
5. A bidirectional line-offset map, so that evidence line numbers point into the original file

### 5.4 Download→execute chain detection

Requirements §8 stresses `download → execute` rather than a single-point match.
This is implemented as a **three-segment token sequence match**:

```
segments = [ NET_FETCH(src) , ARCHIVE|archive , EXEC(shell) ]
the chain rule matches the sequence within one command or two adjacent lines,
and the severity is raised to CRITICAL
```
The output must name both the src and the sink position (`evidence.secondary`).

### 5.5 Safety limits on directory traversal

Against symlink loops, traversal outside the skill, and oversized files:

- `follow_links(false)`; a symlink is only recorded as `FS_SYMLINK_OUTSIDE`, never followed
- Maximum depth 12 by default, maximum single file 4 MiB (over that → `INFO`, not parsed)
- Binary files (not UTF-8) are skipped and recorded
- `.git/`, `node_modules/`, `target/`, `__pycache__/` are explicitly excluded

---

## 6. The hash specification (the foundation of reproducible installs)

**Directory digest algorithm `sgdir-v1` (byte-for-byte equivalent to
`src/hash.rs::digest_dir`):**

```
1. Walk the files (without following symlinks), skipping the exclusions, and sort
   by POSIX-style relative path ('/'-separated, Unicode NFC) ascending
2. Produce one record per file, whose byte sequence is
     R_i = b"sfg1\0" + relpath_bytes + b"\0" + mode + b"\0" + sha256_hex(content) + b"\0"
   where mode is b"755" (executable) or b"644" (otherwise); sha256_hex is the
   lowercase 64-character hex digest of the file content, without the "sha256:" prefix
3. digest = SHA256( b"SKILLGUARD-DIR-v1\0" + R_1 + R_2 + ... + R_n )
   This is a **single streaming hash**: the records are concatenated straight into
   one hash, not "SHA256 each file, then concatenate the digests"
4. Output "sha256:" + hex(digest)
```

`mode` only encodes the executable bit (`755` / `644`), so a differing umask across
platforms cannot make the result irreproducible. Paths are normalized to Unicode
NFC, so an NFD name from macOS and an NFC name from Linux produce the same digest.
**Explicitly excluded**: the directories `.git/`, `node_modules/`, `__pycache__/`,
`.venv/`, `target/`, and the files `SKILLGUARD.lock`, `.DS_Store`, `Thumbs.db`
(`SKILLGUARD.lock` is excluded to prevent self-reference).

This is incompatible with `skills-lock.json`'s `computedHash`: `skillguard import`
reads a foreign lockfile and **preserves the original `computedHash`** as
`legacy_digest` for retrospective checks. It is not written into `content_digest`,
because that is an `sgdir-v1` digest.

---

## 7. Provenance collection

```yaml
provenance:
  source: github:user/financial-analysis
  repository: https://github.com/user/financial-analysis
  commit: <40-hex full sha>          # short SHAs / branch names / tags are forbidden
  tree_digest: "sha256:..."
  author: <git author, informational only>
  license: MIT                        # SPDX expression
  license_source: frontmatter | LICENSE file | unknown
  observed_at: 2026-10-07T12:00:00Z  # second precision, to avoid lockfile churn
```

- **Short SHAs / tags / branches are rejected** (the same lesson as `skills-lock`:
  drift means non-determinism).
- `provenance::git` makes read-only `git` subprocess calls (`rev-parse`, `config`,
  `log -1`). We do not pull in `git2`: libgit2's TLS/certificate behaviour would
  bring in network and supply-chain surface, and the MVP only needs to read a local
  repository. **If the input is not a git repository, `source`/`commit` are null and
  `provenance.incomplete: true` is set explicitly.**
- SPDX licenses: the `spdx` crate validates the expression; an unknown license is
  normalized to `LicenseRef-*` rather than raising an error.

---

## 8. Policy and decisions

```yaml
policy_version: 1
policy:
  network:
    outbound:
      allow_domains: ["api.example.com"]
      deny_domains: ["*"]
  filesystem:
    allow_paths: ["./data/**"]
    deny_paths: [".ssh/**", ".env"]
  shell:
    deny: ["sudo", "rm -rf"]
  secrets:
    access: false
  findings:
    deny_severity: CRITICAL
    require_approval_severity: HIGH
```

`PolicyDecision` has four states: `Allow` / `Warn` / `RequireApproval` / `Deny`.
`Deny` is the only state that blocks installation (invariant I1).

**Approvals** are written into `SKILLGUARD.lock` under `approvals[]` (reviewer +
reason + timestamp + a summary of the basis for the decision). Unlike
`skills-lock`'s PR-scoped approvals, the MVP uses **durable approvals**, and records
the `content_digest` the approval was based on — if the content changes, the
approval automatically lapses (that is its weakness; we avoided it at the design
stage).

---

## 9. Lockfile design

```yaml
lockfile_version: 1
skills:
  financial-analysis:
    source: github:user/financial-analysis
    commit: <40-hex>
    content_digest: "sha256:..."
    uncommitted: false         # the worktree was dirty when the lock was written, so `commit` does not contain this content
    legacy_digest: null
    version: 1.2.0
    license: MIT
    declared_permissions:      # source: frontmatter (must not be polluted by scan results)
      network: { outbound: ["api.example.com"] }
    observed_capabilities:     # source: the scanner
      network: { outbound: ["api.example.com", "evil.example.com"] }
    mismatches:                # ⭐ a snapshot of the differences, as they stood at install time
      - capability: network.outbound
        kind: under_declared
        detail: "evil.example.com"
        severity: HIGH
    dependencies:
      - { ecosystem: pypi, name: pandas, version_spec: ">=2.0" }
    policy_decision: allow
    approved_by: null
    observed_at: 2026-10-07T12:00:00Z
```

Relationship to `skills-lock.json`: **not a replacement, only read and migrate**
(the requirements do not forbid interoperability, and this is the largest ecosystem
entry point). `skillguard import skills-lock` produces an initial
`SKILLGUARD.lock`, bringing every hash-pinning behaviour inside this tool's policy
gate.

---

## 10. CLI surface

> This section is the design-time plan; the authoritative surface is
> `skillguard --help` and the command table in the README. `add` / `install` /
> `update` are deferred by design (issue #9) and do not currently exist; every
> other command is implemented.

```
skillguard scan <path>...                 # evidence-first report + exit code
skillguard inspect <path>...              # list capabilities / dependencies only, no verdict
skillguard diff <path>...                 # declared vs observed
skillguard policy-check <path>...         # evaluate policy
skillguard verify [path]... [--lockfile]  # the source + commit + digest triple check
skillguard add <source>                   # (not implemented) resolve → scan → policy → block/approve → write lock → install
skillguard install                        # (not implemented) install strictly from the lockfile
skillguard update [name]                  # (not implemented) re-resolve; must pass policy and be re-approved
skillguard lock <path>...                 # write the current state into the lockfile
skillguard approve <path>                 # record an approval
skillguard import <file> [--out]          # skills-lock.json / package.json+npm migration
skillguard rules                          # the rule catalogue (id / severity / description / how to turn it off)
```

**Exit codes**: `0` pass · `1` policy violation or `--fail-on` reached · `2`
integrity failure · `3` usage error.
(There is no `4`; every internal error is returned as `3`, see `exit` in
`src/lib.rs`.)
`--fail-on <SEVERITY>`, `--format text|json|sarif|markdown`, `--no-color`.

---

## 11. Test strategy (per requirements §21.10; current state in `tests/`)

> The following was the design-time target. What is implemented is 2, 4 and 5;
> number 1 is enforced by regenerating and checking `docs/RULES.md` via
> `every_rule_id_in_the_catalogue_is_documented` (there is no `rule_registry.rs`);
> 3 (`tests/golden/` snapshots) and 6 (property tests) are not implemented yet.

1. **Rule → test mapping**: when adding a rule, make sure `rules --format markdown`
   and `docs/RULES.md` agree, and add a fixture for it (see item 2).
2. **The four fixture quadrants**: safe (zero findings) / malicious (must trip) /
   suspicious (evidence without a severity bump) / obfuscated (must trip after
   normalization) / edge_cases (must not panic).
3. **Golden output**: `tests/golden/` snapshots of the text and json output, to
   prevent an unintended change from breaking a user's CI.
4. **Hash determinism tests**: the same content twice yields the same digest; a
   single changed byte must change it.
5. **Invariant tests**: zero writes into an agent directory on deny (using a temp
   directory and asserting the filesystem did not change).
6. **Property tests** (optional, `proptest`): no input may panic.

---

## 12. CI and release

- `cargo fmt --check` / `cargo clippy -- -D warnings` / `cargo test` / `cargo deny check`
- The minimum supported Rust version is pinned; prebuilt binaries are provided
  (linux x86_64/arm64, macOS, windows) plus `install.sh`
- Later, a GitHub Action: `skillguard action@v1`, reading SARIF, uploading to Code
  Scanning, exiting 1 on a violation

## 13. Explicitly out of scope (recorded at the architecture level)

Web Registry / SaaS / LLM / Agent Runtime / Autonomous Security Agent / a remote
scanning service / a home-grown model / scanning the whole MCP ecosystem /
distributed scheduling.
