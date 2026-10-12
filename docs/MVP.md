# SkillGuard — MVP scope and roadmap

Stack: Rust (one binary, offline, zero LLM). This document defines the delivery
boundaries and the acceptance criteria.

> **Implementation status (2026-10-07).** The phase numbers in this document have
> drifted out of sync with the repository's later numbering: Phases 1–3 here are all
> implemented; Phase 4 here (`add`/`install`/`update`) is deferred by design (issue
> #9); Phase 5 here (CI / SARIF / Action) is implemented, and the repository calls it
> Phase 4. The authoritative status is [README](../README.md#status) and the issue
> board. This document is kept as the basis for scope and acceptance criteria.

---

## 1. The naming decision (open; `skillguard` for now)

Research turned up systems with the same name: **arXiv 2606.03024 "SkillGuard: A
Permission Framework for Agent Skills"** and **2605.10990 "Skill Drift Is Contract
Violation"**.

| Option | Advantage | Disadvantage |
|---|---|---|
| **A. Keep `skillguard`** (current) | The GitHub URL exists and the repository name is settled | Shares a name with a paper, so the README must state the relationship |
| B. Rename to `skilltrust` / `sgt` | No conflict | Requires recreating the repository, and `SkillGuard` is the more fitting word |

**Recommendation: keep A**, and state in the README's first paragraph that "this
project is ≠ the official implementation of the arXiv 2606.03024 paper; we implement
the pre-install, purely static version of its permission-manifest idea". That is a
credibility gain, not a loss. **The name is finalised before Phase 2 begins.**

CLI binary name: `skillguard`.

---

## 2. Scope decisions: aligning with the research findings

The phase split in requirements §20 is basically sound, but research led to two
adjustments:

**Adjustment 1: why Phase 3 (provenance/lockfile) is merged forward into Phase 2**
`skil-lock` already occupies the capability-lockfile space. Our lockfile must be
**designed from the start to contain `declared_permissions` + `mismatches`**,
otherwise it cannot be refactored later. So the lockfile **schema** is defined in
Phase 2, and **provenance collection** (git metadata) can stay in Phase 3.

**Adjustment 2: Phase 1 reads the declared field**
The `permissions` in frontmatter (or `skillguard.permissions`) is parsed and
preserved from Phase 1 onward; Phase 1 just does not diff it. That way fixtures can
carry declarations from day one.

---

## 3. Phase 1 — Scanner (the first deliverable)

### Deliverables
`skillguard scan <path>...` + `inspect` + `rules`
- SKILL.md frontmatter parsing (including the `permissions` declaration field)
- Safe directory traversal
- The normalization pipeline (NFKC / zero-width / base64 shadow text / homoglyph marking)
- Rule sets: secrets / shell / network / filesystem / download (chains) / injection (heuristics) / obfuscation
- Output: text / json / sarif
- Exit codes: controlled by `--fail-on <SEVERITY>`
- Severities: INFO / LOW / MEDIUM / HIGH / CRITICAL
- Every finding must carry `file` + `line` + `evidence` (invariant S3)

### The rule ID list (all of these must be implemented in Phase 1)
```
SECRET_PRIVATE_KEY, SECRET_AWS_ACCESS_KEY, SECRET_GITHUB_TOKEN, SECRET_GENERIC_ASSIGN,
SECRET_JWT, SECRET_PATH_READ, SECRET_ENV_DUMP,
SHELL_EXEC, SHELL_PRIVILEGE_ESCALATION, SHELL_DESTRUCTIVE, SHELL_EVAL,
NET_HTTP_CLIENT, NET_FETCH_CALL, NET_DOMAIN_LITERAL, NET_DYNAMIC_URL,
FS_SENSITIVE_PATH, FS_ABSOLUTE_PATH, FS_HOME_ACCESS, FS_RECURSIVE_WALK,
FS_PATH_ESCAPE, FS_SYMLINK_OUTSIDE,
DL_PIPE_TO_SHELL, DL_REMOTE_INSTALL, DL_UNTRUSTED_DOMAIN,
DL_PASSWORD_ARCHIVE, DL_CHAIN_FETCH_EXECUTE, DL_BASE64_BLOB,
PI_INJECTION_OVERRIDE, PI_SYSTEM_IMPERSATION, PI_CONCEALMENT,
PI_EXFIL_INSTRUCTION, PI_DESCRIPTION_MISMATCH,
OBFUSC_ZERO_WIDTH, OBFUSC_HOMOGLYPH, OBFUSC_TRACKING_PIXEL,
PERSIST_AGENT_CONFIG, PERSIST_SHELL_RC, PERSIST_HOOK,
DEP_TYPOSQUAT, DEP_CUSTOM_REGISTRY, DEP_UNPINNED_SCRIPT,
LICENSE_MISSING, LICENSE_MISMATCH
```

### Acceptance criteria
1. **Every** fixture under `tests/fixtures/malicious/` trips at least one expected
   rule; the test lists `expected_rules` explicitly and asserts that the hit set
   **contains** it (equality is not required).
2. **Zero findings** (severity ≥ LOW) under `tests/fixtures/safe/`.
3. Fixtures under `tests/fixtures/obfuscated/` trip the same rules as the equivalent
   content under `malicious/`.
4. `tests/fixtures/edge_cases/` (empty file, 10 MB single line, symlink loop, binary,
   NUL bytes, a huge number of tiny files) **do not panic**, and the exit code is in
   {0, 1}.
5. No network access during a scan (the suite passes with networking disabled).
6. `scan --format sarif` passes `sarif-validator` schema validation.
7. A single 200 KB SKILL.md scans in < 100 ms (release build, 4 cores).

---

## 4. Phase 2 — Capability / Permissions / Policy (the differentiation core)

### Deliverables
`skillguard inspect` / `diff` / `policy check` / `approve`
- Deriving the `CapabilitySet` (observed)
- Parsing and normalizing `PermissionDecl` (declared)
- The **`declared_vs_observed()` diff**: three outcomes
  - `over_declared`: declared but never observed (does not block; flags redundancy)
  - `under_declared`: observed but not declared (**blocks**, HIGH)
  - `conflicting`: declarations contradict each other (blocks)
- The policy engine (`SKILLGUARD.policy.yaml`) with four-state decisions
- Per-rule `ignore` and global `exclude`

### Determinism and false positives in the diff
The key design point: **only count an observation as `under_declared` when it cannot
be explained as documentation.**
- Shell commands: `git` / `ls` appearing in an example is usually not a capability
  claim → they are only observed and counted in script files
- URLs: a link in the documentation is an explanatory reference; only URLs inside
  scripts/code count as observed network
- File paths: likewise, only paths in code count

This rule is what brings `under_declared` precision to a usable level. **A precision
test set must exist in the first week of Phase 2** (at least 30 real skills,
hand-labelled); below 0.8, it falls back to "report but do not block".

### Acceptance criteria
1. `diff` reaches `under_declared` precision ≥ 0.8 and recall ≥ 0.5 over 30 real skills.
2. `policy check` returns `Deny` for any skill with outbound capability when
   `network.allow: false`.
3. On `deny`, the filesystem snapshot is unchanged (invariant S2, with an assertion test).
4. An illegal field or type in the policy file produces a clear error rather than
   being silently ignored.

---

## 5. Phase 3 — Hash / Provenance / Verify

### Deliverables
`skillguard hash` / `verify` / `lock` / `import`
- The `sgdir-v1` directory digest (architecture §6)
- git provenance collection (short SHAs / tags / branches rejected)
- SPDX license identification and expression validation
- The `SKILLGUARD.lock` v1 schema
- `import skills-lock.json` (interoperability, see research §2.5)

### Acceptance criteria
1. The same directory digested twice is identical; a 1-byte change must change it
   (verified in CI on 3 platforms).
2. `verify` detects: a commit mismatch, a digest mismatch, and a hand-edited lockfile.
3. `import skills-lock.json` preserves `computedHash` as `legacy_digest`. An imported
   entry has **no** `sgdir-v1` digest, so `verify` explicitly reports "no content
   digest, re-run `lock`" rather than comparing a foreign hash against this tool's
   digest (the `legacy_digest` algorithm is unknown, so comparing the two could only
   produce a false mismatch).
4. A tag or branch as a version input is rejected with an explanation.

---

## 6. Phase 4 — add / install / update

### Deliverables
- Source specs: `github:owner/repo[/path]`, `git+https://`, `path:` (local)
- The `add` orchestration: resolve → scan → diff → policy → (block | approve) → write
  lock → install
- The agent directory registry (architecture §2 `agents.rs`, the single source of truth)
- `install` strictly from the lockfile (a content mismatch fails; it never silently
  reinstalls)
- `update` runs the whole flow again; a digest change → **the old approval lapses
  automatically**

### Acceptance criteria
1. `add` on a CRITICAL skill is blocked and nothing is written into the agent directory.
2. After `approve`, `install` succeeds and `SKILLGUARD.lock` carries the approver, the
   timestamp and the basis digest.
3. When the lockfile digest disagrees with disk, `install` fails with exit code 2.
4. When `update` changes the digest, installation is refused unless re-approved.

---

## 7. Phase 5 — CI / SARIF / Action

- `skillguard/action@v1`: reads SARIF and uploads to Code Scanning
- `--fail-on` and `--format markdown` produce a PR comment
- The rule catalogue is documented (`skillguard rules --markdown`)
- Where needed it can coexist with `skil-lock`'s approvals file (we emit a suggested
  snippet, we do not force it)

---

## 8. Deferred / out of scope

| Item | Reason |
|---|---|
| Registry / search / publish | Requirements §6 forbids it; it is also where we are not competing |
| LLM semantic analysis | Requirements §3 forbids it as a core. Possible as a future optional layer |
| Runtime sandbox / enforcement | The territory of the arXiv SkillGuard / AgentBound |
| tree-sitter cross-statement dataflow | Phase 1 uses a window join; introduced only if precision is insufficient |
| Multi-language vulnerability database integration | Phase 1 only detects impersonation/registry issues; a real vulnerability DB goes through OSV (Phase 5+) |
| Telemetry / cloud | Requirements §4, local-first |

---

## 9. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `under_declared` false-positive rate too high | Medium | Blocks users' normal installs | Count only in code files; "report but do not block" first to accumulate data before enabling blocking |
| `skil-lock` gets to declared-vs-observed first | Medium | Weakens the differentiation | Publish the `SKILLGUARD.lock` spec first (CC BY), taking the specification slot as `skil-lock` did |
| Confusion from the shared name with the arXiv SkillGuard | Already happened | Medium | State the complementary relationship and cite it in the README's first paragraph |
| The rule set is bypassed (adversarial obfuscation) | High | Medium | The normalization pipeline plus continually added adversarial fixtures; openly state "cannot be complete" |
| Development speed of one person / one model | Medium | Medium | Each rule is independently addable; fixtures drive development |
| Boundary bugs in Rust regex/parsing | Medium | High | clippy `-D warnings`, `cargo deny`, invariant assertion tests |

---

## 10. Milestones

| Stage | Content | Exit condition |
|---|---|---|
| M1 | All of Phase 1 | All 7 acceptance criteria in §3 pass |
| M2 | All of Phase 2 | All 4 acceptance criteria in §4 pass |
| M3 | All of Phase 3 | All 4 acceptance criteria in §5 pass |
| M4 | All of Phase 4 | All 4 acceptance criteria in §6 pass |
| M5 | All of Phase 5 | The Action produces Code Scanning results in an example repository |

**MVP success test** (per requirements §23): `skillguard add <suspicious-skill>`
reliably reports all 7 risk classes before installation (credential access / shell
execution / filesystem / network / suspicious download / prompt injection / dangerous
dependencies); `policy check` blocks a violating skill; `verify` confirms the
source+commit+hash triple binding; and `install` completes a reproducible install from
the lockfile.
