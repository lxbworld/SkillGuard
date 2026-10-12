# SkillGuard — Threat Model

This document describes two things at once: (A) the threats SkillGuard defends
against **as a pre-install gate**, and (B) the threats a scanned Skill poses when
it **attacks SkillGuard itself**.

> Core principle (requirements §22): **Treat the scanned Skill as hostile input.**
> We do not sandbox at runtime, so every attack surface has to be closed before we
> have "read the bytes".

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1 Credentials | `~/.ssh`, `.env`, `.aws/credentials`, CI tokens — a Skill's scripts run with the user's privileges |
| A2 The user's filesystem | Project files, home directory, any writable path |
| A3 Agent instruction integrity | SKILL.md is injected into the model's context, which is equivalent to "issuing instructions as the user" |
| A4 Agent configuration | `.claude/settings.json` and friends can be tampered with to persist a backdoor |
| A5 The set of installed Skills | Poison one and it spreads sideways |
| A6 The supply-chain record | Tamper with provenance / the lockfile and every check above it is worthless |
| A7 SkillGuard's own integrity | Bypass it and the whole trust layer fails |

---

## 2. Trust boundaries

```
 TB0  Developer/CI itself    —— trusted
      ───────────────────────────────────────────────
 TB1  SkillGuard process     —— kernel-level isolation (process / filesystem permissions)
      ───────────────────────────────────────────────
 TB2  Parser boundary        —— parsing SKILL.md / YAML / JSON
      ───────────────────────────────────────────────
 TB3  Rule engine boundary   —— untrusted text vs extracted structured tokens
      ───────────────────────────────────────────────
 TB4  Install write boundary —— the first crossing from "read-only" to "write into an agent directory"
      ───────────────────────────────────────────────
 TB5  Git boundary           —— third-party remote repositories (not under our control)
      ───────────────────────────────────────────────
 TB6  Network boundary       —— the MVP never crosses it (except installing from a Git source)
```

**TB4 is the only state transition**: before it, a Skill is a pile of bytes; after
it, the Skill is part of the agent. Every blocking decision must be complete before
TB4 (invariant I1).

---

## 3. Threats from a scanned Skill (T1–T10)

### T1 Prompt injection
**Target** A3. **Entries** the `SKILL.md` body, `references/*.md`, `assets/*.md`.
**Techniques**: `ignore previous instructions`, a forged system message,
`do not tell the user`, base64- or Unicode-obfuscated instructions, hidden HTML
comments, and luring the agent into reading other files and exfiltrating them.

**Detection (deterministic)**
- An injection phrase table (case-insensitive, matched on the normalized view):
  `PI_INJECTION_OVERRIDE` / `PI_SYSTEM_IMPERSATION` / `PI_CONCEALMENT` /
  `PI_EXFIL_INSTRUCTION`
- Shadow text (base64 decode candidates) rescanned
- Description-vs-behaviour mismatch: `PI_DESCRIPTION_MISMATCH` (the frontmatter
  description does not match what the body can do)

**Residual risk**: **coverage cannot be guaranteed.** The semantic surface of
natural-language injection is far larger than the rule surface.
**Honest conclusion**: detection ≠ prevention. SkillGuard's job is to **force a
human to read the evidence** (it prints the exact line number and the original
text), not to convict automatically. Any claim of "zero false negatives" is false.
A future optional semantic layer (the Optional AI Layer of requirements §3) must
not become the only line of defence either.

### T2 Credential theft
**Techniques**: reading `~/.ssh/id_rsa`, `.env`, `~/.aws/credentials`,
`.git-credentials`; dumping `process.env` wholesale; `printenv`; reading shell
history.

**Detection**: `SECRET_PATH_READ` (a path table plus fuzzy matching),
`SECRET_ENV_DUMP` (a whole `env` / `printenv` / `os.environ`),
`SECRET_EXFIL_CHAIN` (a credential path and a network sink in the same place →
CRITICAL).
**Must distinguish**: `export FOO=$(cat key.pem)` (real) from a document saying
"best practice for reading ~/.ssh" (explanatory) — mark the latter with
`Confidence` rather than raising severity.

### T3 Hardcoded secrets
`SECRET_PRIVATE_KEY` / `SECRET_AWS_ACCESS_KEY` / `SECRET_GITHUB_TOKEN` /
`SECRET_GENERIC_ASSIGN` / `SECRET_JWT`. High-entropy detection needs care:
**judge only by known prefixes and structural patterns**, so that a sha256 or a
commit hash is not mistaken for a token (a common source of false positives, which
requires hash allowlist patterns).

### T4 Shell execution and privilege escalation
`sudo`, `chmod 777`, `rm -rf`, `eval`, `exec`, `python -c`, `base64 -d | sh`,
`os.system`, `subprocess(..., shell=True)`. **The presence of a command is not
malice**; emit a risk plus the evidence.

### T5 Download-and-execute chains
`curl URL | sh`, `wget -O- URL | bash`,
`powershell IEX(New-Object Net.WebClient).DownloadString`, `pip install http://...`,
`npm i --registry=<unofficial>`, a password-protected zip, `chmod +x` after a
download.
→ the `DL_CHAIN_*` rules, which are CRITICAL on a match and whose evidence names
both the source and the sink.

### T6 Dangerous dependencies / impersonating packages
`requsts`, `python-dateutil2`, `numpyy`, `cross-env`, `lodash.`, plus a typosquat
heuristic (edit distance against a table of well-known package names). The
dependency list comes from statically parsing `requirements.txt` /
`pyproject.toml` / `package.json` / `Cargo.toml`.

### T7 Overwriting and persistence
Writing a hook into `.claude/settings.json`, `~/.claude/CLAUDE.md`, `AGENTS.md`,
`.git/hooks/*`, crontab, shell rc files.
→ the `PERSIST_*` rules (Phase 1 may report INFO/LOW only; Phase 2 raises them).

### T8 Cross-Skill / cross-agent reference escapes
`@../other-skill/SKILL.md`, reading all of `~/.claude/skills/`, treating the
contents of another Skill as instructions.
→ `REF_OUTSIDE_SKILL` plus the out-of-bounds accesses in the capability diff.

### T9 Obfuscation and hidden text
base64 blobs, zero-width characters, homoglyphs, instructions inside HTML comments,
over-long invisible runs, and zero-width links/images in Markdown
(`![](` plus a tracking-pixel domain).
→ the `OBFUSC_*` rules, with `DL_BASE64_BLOB` as a supporting signal.

### T10 Licence and compliance
An undeclared licence, a declaration that disagrees with the LICENSE file, and a
**restrictive licence used for commercial distribution** (the GPL/AGPL copyleft,
"non-commercial" clauses, unknown provenance).
→ the `LICENSE_*` rules; Phase 3 adds SPDX expression validation.

---

## 4. Threats to SkillGuard itself (T11–T17)

This section is the part where **a security tool has to defend itself first**.

### T11 Parser DoS
**Attack**: a 10 MB single-line YAML file, YAML nested 500 levels deep
(billion-laughs-style entity expansion), a giant JSON document, a huge number of
tiny files (inode exhaustion), regex backtracking (ReDoS).

**Mitigation**
- Serialize as **JSON**; YAML is used only for policy/lockfile and with a depth cap
  in `serde_yaml`. A read failure is treated as untrusted and produces
  `PARSE_FAILED` (no panic).
- Caps: 4 MiB per file, depth 12, 10,000 files (over a cap → `INFO` and expansion
  stops)
- Only `regex` (linear time, no backtracking); hand-written backtracking NFA
  regexes are **forbidden**
- Every parse entry point is wrapped in `catch_unwind`; a panic becomes an error
  code and never reaches the user

### T12 Path traversal / zip-slip hazards
**Attack**: `scripts/../../../../etc/cron.d/x`,
`references/~/....ssh/id_rsa`.

**Mitigation**: after `path-clean` normalization the path must still be inside the
skill root, otherwise we record a finding and **do not read** the file. All reads go
through the single entry point `SkillGuard::resolve_safe_path(root, rel) -> Result<Path>`.

### T13 Symlink attacks
**Attack**: `scripts/link -> ~/.ssh`, or a symlink loop `a -> b -> a`.

**Mitigation**: `follow_links(false)`; a symlink pointing outside the root produces
`FS_SYMLINK_OUTSIDE` (MEDIUM) and is not followed. On Windows a junction is treated
as a symlink too.

### T14 Parser-level attacks from untrusted files
- Control characters (ANSI escapes / zero-width) embedded in `SKILL.md` →
  **terminal injection**: a malicious Skill can use ANSI sequences in a filename or
  description to manipulate what the user sees in their terminal and forge scan
  results.
  **Mitigation**: every string written to the terminal passes through
  `strip_ansi + NFC normalization + length truncation` first.
- A very long single line garbles terminal wrapping → a per-field output cap (for
  example 200 characters plus `…`).

### T15 Lockfile poisoning
**Attack**: tamper with `commit` / `content_digest` / `policy_decision` in
`SKILLGUARD.lock` so that a malicious skill looks compliant.

**Mitigation**
- The tool has exclusive ownership of writes to the lockfile (a `generated_by`
  field, plus a `verifier` recording the CLI version)
- `verify` **recomputes** the digest and compares it to the lockfile; it trusts no
  recorded field
- The lockfile itself lives in git, so a PR diff is the audit surface; `skillguard
  diff` shows how the capability surface changed
- When reading a lockfile, `source` is validated against a scheme allowlist
  (`file://`, UNC paths and arbitrary `local:` escapes are rejected)

### T16 Timing and environment
- SkillGuard must finish every check before writing to an agent directory
  (invariant I1). If it fails midway it must **leave no half-written state**: write
  to a temp directory and rename atomically.
- It refuses to install into an unexpected directory (the directory table in
  `agents.rs` is the single source of truth; an arbitrary install path is never
  read from an environment variable).

### T17 Approval laundering
**Attack**: use `approve` to turn a `deny` into an `allow`, so the lockfile looks
like "policy allowed this". More generally: an approval record would leave behind
only "somebody approved it", without "which violation they approved", degrading the
audit trail into a result record with no reason (issue #7).

**Decision (chosen deliberately, not an accident of the code)**:
- **A human may override any decision, including CRITICAL.** A security tool's goal
  is to make a decision **readable**, not **impossible**. An engineer who holds the
  context is the final authority; making CRITICAL unoverridable only pushes people
  to hand-edit the lockfile or skip the tool, which is worse.
- **But the override has to be deliberate.** Overriding a `deny` requires an
  explicit `--force`; and with or without `--force`, `policy_decision` always keeps
  the value the engine computed (`deny`). The approval is recorded **alongside** as
  `overrode_decision` plus `overrode_violations`, and never rewrites `deny` into
  `allow`.
- The terminal lists the accepted violations before writing, so the approver sees
  what they signed before it lands on disk.

**Mitigation/test**: assertions in `tests/cli.rs` (without `--force` it refuses and
writes nothing; with `--force` it records `deny` plus the violation list; a clean
skill records `allow` with no override record).

---

## 5. Threat → rule → severity mapping

| Threat | Rule IDs | Default severity |
|---|---|---|
| T1 | `PI_INJECTION_OVERRIDE`, `PI_SYSTEM_IMPERSATION`, `PI_CONCEALMENT`, `PI_EXFIL_INSTRUCTION` | Info |
| T2 | `SECRET_PATH_READ`, `SECRET_ENV_DUMP`, `SECRET_EXFIL_CHAIN` | LOW / HIGH / CRITICAL |
| T3 | `SECRET_PRIVATE_KEY`, `SECRET_AWS_ACCESS_KEY`, `SECRET_GITHUB_TOKEN`, `SECRET_GENERIC_ASSIGN`, `SECRET_JWT` | CRITICAL / HIGH |
| T4 | `SHELL_EXEC`, `SHELL_PRIVILEGE_ESCALATION`, `SHELL_DESTRUCTIVE` | MEDIUM / HIGH |
| T5 | `DL_PIPE_TO_SHELL`, `DL_REMOTE_INSTALL`, `DL_UNTRUSTED_DOMAIN`, `DL_PASSWORD_ARCHIVE`, `DL_CHAIN_FETCH_EXECUTE` | CRITICAL |
| T6 | `DEP_TYPOSQUAT`, `DEP_CUSTOM_REGISTRY`, `DEP_UNPINNED_SCRIPT` | HIGH |
| T7 | `PERSIST_AGENT_CONFIG`, `PERSIST_SHELL_RC`, `PERSIST_HOOK`, `PERSIST_CRON` | MEDIUM |
| T8 | `REF_OUTSIDE_SKILL` | MEDIUM |
| T9 | `OBFUSC_BASE64_BLOB`, `OBFUSC_ZERO_WIDTH`, `OBFUSC_HOMOGLYPH`, `OBFUSC_TRACKING_PIXEL` | MEDIUM |
| T10 | `LICENSE_MISSING`, `LICENSE_MISMATCH`, `LICENSE_RESTRICTIVE` | LOW / MEDIUM |
| T11 | `PARSE_FAILED`, `RESOURCE_LIMIT_EXCEEDED` | INFO |
| T12/13 | `FS_PATH_ESCAPE`, `FS_SYMLINK_OUTSIDE` | HIGH / MEDIUM |
| T15 | `LOCK_DIGEST_MISMATCH`, `LOCK_HAND_EDITED` | HIGH / MEDIUM |
| T17 | the approval record (`overrode_decision` / `overrode_violations`, not a text rule) | records the original decision, never rewrites it |
| — | `MISMATCH_UNDECLARED_CAPABILITY` (produced by the diff, not a text rule) | HIGH |
| — | `POLICY_VIOLATION` (produced by policy) | by violated capability |

---

## 6. Explicitly out of scope

Stated honestly, to avoid offering false comfort:

1. **Runtime behaviour.** We neither execute nor sandbox a Skill. What it does after
   installation is not defended against.
2. **Model-layer vulnerabilities.** SkillGuard cannot stop a model from being
   jailbroken, nor stop it from following a dangerous instruction.
   → that is the territory of the arXiv "SkillGuard" runtime permission framework
   and of AgentBound, not ours.
3. **Semantic-level prompt injection.** The heuristics have a high false-negative
   rate. We print evidence for a human to judge and claim no completeness.
4. **Zero-days and upstream supply-chain poisoning.** If an upstream npm package is
   itself poisoned and its tarball is well-formed, static analysis can only offer a
   weak signal.
5. **Multi-user / enterprise MDM control.** Requirements §6 excludes it.
6. **The MCP server ecosystem.** Requirements §6 excludes it.
7. **Side channels / timing attacks.** Not part of the threat model.

---

## 7. Security invariants (each must be an assertion in a test)

| ID | Invariant |
|---|---|
| S1 | The scanner never `exec`s a scanned file, never makes a network request, and never reads credentials from the environment |
| S2 | When `policy_decision == Deny`, the filesystem snapshot of the agent directory and the skill directory is completely unchanged |
| S3 | Every Finding carries `file` + `line` + the original `evidence` (no evidence, no finding) |
| S4 | The `content_digest` of the same input is identical across machines and operating systems |
| S5 | Every string written to the terminal is cleaned of ANSI / bidirectional control characters (`text::sanitize_controls`); content quoted from a skill additionally gets a 200-character cap (`sanitize_for_display`), and paths use only the former, because truncation would hide a filename |
| S6 | Every path read from disk goes through `resolve_safe_path` |
| S7 | The scanner does not panic on any input (including random bytes) |
| S8 | In the lockfile, `declared_permissions` and `observed_capabilities` cannot be assigned to each other at the type level |
| S9 | An approval never rewrites `policy_decision` from `deny` to `allow`; overriding a `deny` requires an explicit `--force`, and the overridden violations are recorded together with the approval (T17) |
