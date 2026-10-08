# Rule reference

Generated from `skillguard rules --format markdown`. Do not edit by hand:
`tests/invariants.rs::the_rule_reference_matches_the_code` regenerates it and
fails if the committed file drifts from the code (issue #4).

Every finding carries a file, a line and the original text, and every rule below
is deterministic: no model is called, ever.

## How to read a rule id

`PREFIX_SUBJECT`, where the prefix names the threat class:

| prefix | class |
|---|---|
| `SECRET_` | credentials and secrets |
| `SHELL_` | shell execution and privilege |
| `NET_` | network access |
| `FS_` | filesystem access |
| `DL_` | download and execute chains |
| `PI_` | prompt injection (heuristic, see `docs/THREAT_MODEL.md` T1) |
| `OBFUSC_` | obfuscation and hidden text |
| `PERSIST_` | persistence |
| `DEP_` | dependencies |
| `LICENSE_` | licensing |
| `MISMATCH_` | declared vs observed permissions |
| structural ids | computed rather than pattern-matched (`PARSE_FAILED`, `RESOURCE_LIMIT_EXCEEDED`, `DL_CHAIN_FETCH_EXECUTE`, ...) |

## How to silence a rule

Silencing is a **policy** decision, so it is recorded in the policy file rather
than passed as a CLI flag that nobody can audit:

```yaml
# SKILLGUARD.policy.yaml
policy_version: 1
findings:
  ignore: ["LICENSE_MISSING"]
```

The rule is still evaluated and still available from `skillguard inspect`; the
report simply stops carrying it, and `--fail-on` stops failing on it. Prefer
fixing the finding. An ignored rule is a decision someone made, and the policy
file is where that decision is legible.

## The catalogue

| rule | severity | capability | what it catches | how to fix it | how to silence it |
|---|---|---|---|---|---|
| `DEP_CUSTOM_REGISTRY` | HIGH | package_install | A package manager is pointed at a non-default registry or index | Use the default registry. A custom index removes the ecosystem's review process. | `findings.ignore: ["DEP_CUSTOM_REGISTRY"]` |
| `DEP_TYPOSQUAT` | HIGH | package_install | A dependency name closely resembles a popular package | Verify the name character by character. Typosquats are the cheapest supply-chain attack. | `findings.ignore: ["DEP_TYPOSQUAT"]` |
| `DEP_UNPINNED_SCRIPT` | MEDIUM | package_install | Executable code is fetched from an unpinned ref, so its content is not reproducible | Pin a commit or a versioned release, and verify a digest. | `findings.ignore: ["DEP_UNPINNED_SCRIPT"]` |
| `DL_BASE64_BLOB` | LOW | - | A long base64 blob is embedded; its decoded content is scanned separately | If this decodes to code or instructions, inline it so it can be reviewed. | `findings.ignore: ["DL_BASE64_BLOB"]` |
| `DL_CHAIN_FETCH_EXECUTE` | CRITICAL | shell.execute | Fetch, transform and execute in one flow: download to execute | Break the chain. Each hop must be inspectable and digest-verified. | `findings.ignore: ["DL_CHAIN_FETCH_EXECUTE"]` |
| `DL_PASSWORD_ARCHIVE` | HIGH | shell.execute | An archive is opened with a hardcoded password, which is how malware is smuggled | Reject password-protected archives in a distributed skill. | `findings.ignore: ["DL_PASSWORD_ARCHIVE"]` |
| `DL_PIPE_TO_SHELL` | CRITICAL | shell.execute | Downloaded content is piped straight into an interpreter | Never execute fetched content. Download to a file, verify its digest, then run it. | `findings.ignore: ["DL_PIPE_TO_SHELL"]` |
| `DL_POWERSHELL_IEX` | CRITICAL | shell.execute | Downloaded text is evaluated as PowerShell | Remove it. This is the Windows equivalent of piping a download into a shell. | `findings.ignore: ["DL_POWERSHELL_IEX"]` |
| `DL_REMOTE_INSTALL` | HIGH | package_install | A package or executable is installed directly from a URL, bypassing the registry | Install from a named registry at a pinned version so the artifact has an identity. | `findings.ignore: ["DL_REMOTE_INSTALL"]` |
| `DL_UNTRUSTED_DOMAIN` | MEDIUM | network.outbound | A low-reputation TLD or a raw IP endpoint is contacted | Replace it with a named, accountable endpoint. | `findings.ignore: ["DL_UNTRUSTED_DOMAIN"]` |
| `FS_ABSOLUTE_PATH` | MEDIUM | filesystem.read | A sensitive system or user path is accessed by absolute path | Confirm the access is required and declare the exact path. | `findings.ignore: ["FS_ABSOLUTE_PATH"]` |
| `FS_HOME_ACCESS` | LOW | filesystem.read | The home directory is referenced | Prefer a project-relative path. Home-directory access reaches config and credentials. | `findings.ignore: ["FS_HOME_ACCESS"]` |
| `FS_MODE_UNRESOLVED` | INFO | filesystem.read | An open() mode could not be resolved statically; the path is counted as a read | If this path is written, use a literal mode (`'w'`, `'a'`, `'x'`) or declare the write, so the capability is not under-reported. | `findings.ignore: ["FS_MODE_UNRESOLVED"]` |
| `FS_PATH_ESCAPE` | HIGH | filesystem.read | The path traverses above the skill directory | Remove the traversal. Anything outside the skill directory needs explicit approval. | `findings.ignore: ["FS_PATH_ESCAPE"]` |
| `FS_RECURSIVE_WALK` | MEDIUM | filesystem.read | The skill walks the filesystem recursively | Scope the walk to a known subdirectory. An unscoped walk can read unrelated projects. | `findings.ignore: ["FS_RECURSIVE_WALK"]` |
| `FS_SENSITIVE_PATH` | HIGH | filesystem.read | A sensitive dotfile or key store is opened in executable code | Remove the access, or require an explicit declaration and approval. | `findings.ignore: ["FS_SENSITIVE_PATH"]` |
| `FS_SYMLINK_OUTSIDE` | MEDIUM | filesystem.read | A symlink points outside the skill directory | Remove the link. It is an exfiltration primitive even though we refuse to follow it. | `findings.ignore: ["FS_SYMLINK_OUTSIDE"]` |
| `LICENSE_MISMATCH` | MEDIUM | - | The declared license does not match the LICENSE file | Make the declaration and the file agree. | `findings.ignore: ["LICENSE_MISMATCH"]` |
| `LICENSE_MISSING` | INFO | - | No license is declared and no LICENSE file is present | Add a license. Redistributable skills need explicit terms. | `findings.ignore: ["LICENSE_MISSING"]` |
| `LICENSE_RESTRICTIVE` | MEDIUM | - | A restrictive or source-available license term is present | Confirm the license permits your intended use before redistributing or depending on it. | `findings.ignore: ["LICENSE_RESTRICTIVE"]` |
| `NET_DOMAIN_LITERAL` | LOW | network.outbound | A hostname literal appears in executable code | Add the host to the declared outbound allowlist, or remove the reference. | `findings.ignore: ["NET_DOMAIN_LITERAL"]` |
| `NET_DYNAMIC_URL` | HIGH | network.outbound | The request target is built at run time, so the destination cannot be reviewed | Resolve the URL to a literal, or pin the host and validate it before the request. | `findings.ignore: ["NET_DYNAMIC_URL"]` |
| `NET_FETCH_CALL` | MEDIUM | network.outbound | Library code performs an outbound network request | Declare every host you contact. | `findings.ignore: ["NET_FETCH_CALL"]` |
| `NET_HTTP_CLIENT` | MEDIUM | network.outbound | A command-line HTTP client makes an outbound request | Declare every host you contact. Undeclared egress is the main exfiltration channel. | `findings.ignore: ["NET_HTTP_CLIENT"]` |
| `OBFUSC_BASE64_PAYLOAD` | HIGH | agent.injection | Base64 content decodes to an instruction pattern | Inline the plaintext so it can be reviewed. | `findings.ignore: ["OBFUSC_BASE64_PAYLOAD"]` |
| `OBFUSC_BIDI_CONTROL` | HIGH | agent.injection | Bidirectional control characters reorder the visible text | Remove them. A permission declaration that renders differently from what it says is an attack. | `findings.ignore: ["OBFUSC_BIDI_CONTROL"]` |
| `OBFUSC_HOMOGLYPH` | MEDIUM | agent.injection | Non-ASCII lookalike characters are used to spell a command | Use ASCII. A command spelled with lookalike characters from another script reads as the real command to a human. | `findings.ignore: ["OBFUSC_HOMOGLYPH"]` |
| `OBFUSC_TRACKING_PIXEL` | MEDIUM | network.outbound | Markdown embeds a remote image, which fetches and reports back without explicit consent | Host images with the skill, or remove them. | `findings.ignore: ["OBFUSC_TRACKING_PIXEL"]` |
| `OBFUSC_ZERO_WIDTH` | MEDIUM | agent.injection | Zero-width characters break up keywords to evade matching | Remove them. Legitimate Markdown does not need them. | `findings.ignore: ["OBFUSC_ZERO_WIDTH"]` |
| `PARSE_FAILED` | INFO | - | SKILL.md frontmatter could not be parsed | Check the YAML. An unparseable skill cannot be validated. | `findings.ignore: ["PARSE_FAILED"]` |
| `PERSIST_AGENT_CONFIG` | MEDIUM | filesystem.write | The skill writes agent configuration, which persists into every later session | A skill must not modify agent configuration. Remove the write. | `findings.ignore: ["PERSIST_AGENT_CONFIG"]` |
| `PERSIST_CRON` | HIGH | shell.execute | Scheduled execution is installed | Remove it. | `findings.ignore: ["PERSIST_CRON"]` |
| `PERSIST_HOOK` | HIGH | shell.execute | A hook is installed that runs automatically with the user's privileges | Hooks are the strongest persistence primitive available. Require explicit approval. | `findings.ignore: ["PERSIST_HOOK"]` |
| `PERSIST_SHELL_RC` | MEDIUM | filesystem.write | A shell startup file is modified, which persists for the user's lifetime | Remove the modification. | `findings.ignore: ["PERSIST_SHELL_RC"]` |
| `PI_CONCEALMENT` | INFO | agent.injection | An instruction to hide behaviour from the user | Remove it. Transparency to the operator is a hard requirement. | `findings.ignore: ["PI_CONCEALMENT"]` |
| `PI_DESCRIPTION_MISMATCH` | MEDIUM | agent.injection | The code reads credentials, but the description does not mention credentials or security | Make the description honest, or remove the credential access. | `findings.ignore: ["PI_DESCRIPTION_MISMATCH"]` |
| `PI_EXFIL_INSTRUCTION` | INFO | network.outbound | An instruction to transmit local data to an external endpoint | Remove it, and treat the skill as compromised until its source is verified. | `findings.ignore: ["PI_EXFIL_INSTRUCTION"]` |
| `PI_INJECTION_OVERRIDE` | INFO | agent.injection | An instruction to disregard prior instructions (prompt injection pattern) | Remove it. No legitimate skill needs to override its operator's instructions. | `findings.ignore: ["PI_INJECTION_OVERRIDE"]` |
| `PI_SYSTEM_IMPERSATION` | INFO | agent.injection | The skill impersonates a system message or asserts a new identity | Remove it. A skill is documentation, not a privileged context. | `findings.ignore: ["PI_SYSTEM_IMPERSATION"]` |
| `RESOURCE_LIMIT_EXCEEDED` | INFO | - | A resource limit was reached while reading the skill | Check for an oversized or generated file, or a symlink loop. | `findings.ignore: ["RESOURCE_LIMIT_EXCEEDED"]` |
| `SECRET_AWS_ACCESS_KEY` | CRITICAL | secrets.read | An AWS access key id is hardcoded | Revoke the key and load credentials from the environment or a secret manager. | `findings.ignore: ["SECRET_AWS_ACCESS_KEY"]` |
| `SECRET_ENV_DUMP` | MEDIUM | secrets.read | The whole process environment is enumerated rather than read by key | Read only the variables you need. A full dump leaks every credential the agent holds. Note: a bare `os.environ` with no keyed access is not matched here because it is ambiguous; capability derivation resolves that case precisely. | `findings.ignore: ["SECRET_ENV_DUMP"]` |
| `SECRET_GENERIC_ASSIGN` | HIGH | secrets.read | A credential-shaped value is assigned to a literal | Confirm it is a placeholder. If it is real, revoke it and inject the value at run time. | `findings.ignore: ["SECRET_GENERIC_ASSIGN"]` |
| `SECRET_GITHUB_TOKEN` | CRITICAL | secrets.read | A GitHub token is hardcoded | Revoke the token and read GITHUB_TOKEN from the environment instead. | `findings.ignore: ["SECRET_GITHUB_TOKEN"]` |
| `SECRET_JWT` | HIGH | secrets.read | A JSON Web Token is hardcoded | Issue tokens at run time; never ship one inside a distributed artifact. | `findings.ignore: ["SECRET_JWT"]` |
| `SECRET_PATH_READ` | HIGH | secrets.read | A credential or key store path is referenced in executable code | Remove the access, or require an explicit declaration and approval for it. | `findings.ignore: ["SECRET_PATH_READ"]` |
| `SECRET_PRIVATE_KEY` | CRITICAL | secrets.read | A PEM private key block is embedded in the skill | Remove the key and rotate it. A key inside a distributed artifact is already compromised. | `findings.ignore: ["SECRET_PRIVATE_KEY"]` |
| `SECRET_PROVIDER_TOKEN` | HIGH | secrets.read | A provider API token is hardcoded | Revoke the token and read it from the environment at run time. | `findings.ignore: ["SECRET_PROVIDER_TOKEN"]` |
| `SHELL_DESTRUCTIVE` | HIGH | filesystem.write | A destructive filesystem, device or history-rewriting operation | Remove it. If it is required, scope it to a temporary directory. | `findings.ignore: ["SHELL_DESTRUCTIVE"]` |
| `SHELL_EVAL` | MEDIUM | shell.execute | Code is evaluated dynamically, which hides what actually runs | Call the command directly. Dynamic evaluation makes the capability surface unreviewable. | `findings.ignore: ["SHELL_EVAL"]` |
| `SHELL_EXEC` | LOW | shell.execute | The skill invokes another interpreter | Read the referenced script before approving. Interpreter invocation hides the real work. | `findings.ignore: ["SHELL_EXEC"]` |
| `SHELL_PRIVILEGE_ESCALATION` | HIGH | shell.execute | The skill escalates privileges or modifies file permissions | Declare the elevated behaviour and justify it. Root is almost never required. | `findings.ignore: ["SHELL_PRIVILEGE_ESCALATION"]` |
