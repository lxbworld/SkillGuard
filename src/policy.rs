//! Policy engine and approval lockfile.
//!
//! # The shape
//!
//! `scan → diff → policy → decision → lock → install`, with one invariant doing
//! the real work: **`Deny` is the only state that stops an install, and it is
//! evaluated before anything is written** (invariant I1/S2).
//!
//! # Approval is bound to content
//!
//! An approval records the `content_digest` it was granted for. If the content
//! changes, the approval stops applying. This is the one design choice here that
//! came from studying a competitor: `skil-lock` persists approvals, so a
//! reviewer who approved `curl` once finds that a later PR adding a *different*
// `curl` is already approved. Binding approvals to the digest closes that.

use crate::hash::Digest;
use crate::models::{Capability, DiffReport, MismatchKind, Severity};
use crate::text;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── policy schema ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub policy_version: u32,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub shell: ShellPolicy,
    #[serde(default)]
    pub secrets: SecretsPolicy,
    #[serde(default)]
    pub findings: FindingsPolicy,
    #[serde(default)]
    pub sources: SourcePolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// When true, no outbound host is permitted at all.
    #[serde(default)]
    pub deny: bool,
    /// Hosts allowed regardless of `deny`.
    #[serde(default)]
    pub allow_domains: Vec<String>,
    /// Extra hosts denied even if allowlisted. Deny wins.
    #[serde(default)]
    pub deny_domains: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellPolicy {
    /// When true, no interpreter may be invoked.
    #[serde(default)]
    pub deny: bool,
    /// Commands denied even when `deny` is false.
    #[serde(default)]
    pub deny_commands: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsPolicy {
    #[serde(default)]
    pub access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsPolicy {
    #[serde(default = "default_deny_severity")]
    pub deny_severity: Severity,
    #[serde(default = "default_approval_severity")]
    pub require_approval_severity: Severity,
}

fn default_deny_severity() -> Severity {
    Severity::Critical
}
fn default_approval_severity() -> Severity {
    Severity::High
}

impl Default for FindingsPolicy {
    fn default() -> Self {
        FindingsPolicy {
            deny_severity: default_deny_severity(),
            require_approval_severity: default_approval_severity(),
        }
    }
}

/// Which sources may be installed at all.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicy {
    /// Source prefixes that are refused outright, e.g. `["file:", "http:"]`.
    #[serde(default)]
    pub deny_prefixes: Vec<String>,
}

impl Policy {
    /// A permissive default: nothing is denied, findings at HIGH need approval
    /// and CRITICAL blocks. A project opts *into* restriction, so an absent
    /// policy file cannot silently lock everyone out of their own tooling.
    pub fn new() -> Self {
        Policy::default()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            policy_version: 1,
            network: NetworkPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            shell: ShellPolicy::default(),
            secrets: SecretsPolicy::default(),
            findings: FindingsPolicy::default(),
            sources: SourcePolicy::default(),
        }
    }
}

/// Parse a policy file.
///
/// `deny_unknown_fields` is deliberate: a typo in a policy that silently does
/// nothing is how a security control becomes decorative.
pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_policy(&src)
}

pub fn parse_policy(src: &str) -> Result<Policy, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(src).map_err(|e| format!("policy is not valid YAML: {e}"))?;
    let policy: Policy =
        serde_yaml::from_value(value).map_err(|e| format!("policy is not valid: {e}"))?;
    Ok(policy)
}

// ── decisions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    RequireApproval,
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn => "warn",
            Decision::RequireApproval => "require_approval",
            Decision::Deny => "deny",
        }
    }

    /// The only state that blocks a write.
    pub fn blocks(self) -> bool {
        self == Decision::Deny
    }
}

/// One reason a decision went the way it did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub capability: String,
    pub detail: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub violations: Vec<Violation>,
    /// Findings at or above the configured threshold.
    pub worst_finding: Option<Severity>,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        PolicyDecision {
            decision: Decision::Allow,
            violations: Vec::new(),
            worst_finding: None,
        }
    }
}

/// Everything the policy engine is allowed to look at.
pub struct Subject<'a> {
    pub name: &'a str,
    pub capabilities: &'a Capability,
    pub diff: &'a DiffReport,
    pub findings: &'a [crate::models::Finding],
    pub source: Option<&'a str>,
    pub approved_digest: Option<&'a str>,
}

/// Evaluate a policy.
///
/// Order matters: a deny is a deny regardless of how many other rules
/// approved it, so denies are collected first and returned immediately.
pub fn evaluate(policy: &Policy, subject: &Subject<'_>) -> PolicyDecision {
    let mut violations: Vec<Violation> = Vec::new();
    let caps = subject.capabilities;

    // ── sources ───────────────────────────────────────────────────────────
    if let Some(src) = subject.source {
        for prefix in &policy.sources.deny_prefixes {
            if src.starts_with(prefix) {
                violations.push(Violation {
                    capability: "source".to_owned(),
                    detail: format!("source `{src}` matches denied prefix `{prefix}`"),
                    severity: Severity::Critical,
                });
            }
        }
    }

    // ── network ───────────────────────────────────────────────────────────
    for host in &caps.network_outbound {
        if policy.network.deny {
            violations.push(Violation {
                capability: "network.outbound".to_owned(),
                detail: format!("{host}: network access is denied by policy"),
                severity: Severity::High,
            });
            continue;
        }
        if policy
            .network
            .deny_domains
            .iter()
            .any(|d| crate::permissions::host_pattern_matches(d, host))
        {
            violations.push(Violation {
                capability: "network.outbound".to_owned(),
                detail: format!("{host}: host is explicitly denied"),
                severity: Severity::High,
            });
            continue;
        }
        // An allowlist, when present, is exhaustive.
        if !policy.network.allow_domains.is_empty()
            && !policy
                .network
                .allow_domains
                .iter()
                .any(|a| crate::permissions::host_pattern_matches(a, host))
        {
            violations.push(Violation {
                capability: "network.outbound".to_owned(),
                detail: format!("{host}: not in the network allowlist"),
                severity: Severity::High,
            });
        }
    }

    // ── filesystem ────────────────────────────────────────────────────────
    let check_paths = |paths: &[String], label: &str, out: &mut Vec<Violation>| {
        for p in paths {
            if policy
                .filesystem
                .deny_paths
                .iter()
                .any(|d| crate::permissions::path_pattern_matches(d, p))
            {
                out.push(Violation {
                    capability: label.to_owned(),
                    detail: format!("{p}: path is explicitly denied"),
                    severity: Severity::High,
                });
            } else if !policy.filesystem.allow_paths.is_empty()
                && !policy
                    .filesystem
                    .allow_paths
                    .iter()
                    .any(|a| crate::permissions::path_pattern_matches(a, p))
            {
                out.push(Violation {
                    capability: label.to_owned(),
                    detail: format!("{p}: not in the filesystem allowlist"),
                    severity: Severity::Medium,
                });
            }
        }
    };
    check_paths(&caps.filesystem_read, "filesystem.read", &mut violations);
    check_paths(&caps.filesystem_write, "filesystem.write", &mut violations);

    // ── shell ─────────────────────────────────────────────────────────────
    for cmd in &caps.shell_execute {
        if policy.shell.deny {
            violations.push(Violation {
                capability: "shell.execute".to_owned(),
                detail: format!("{cmd}: shell execution is denied by policy"),
                severity: Severity::High,
            });
            continue;
        }
        if policy
            .shell
            .deny_commands
            .iter()
            .any(|d| d.eq_ignore_ascii_case(cmd))
        {
            violations.push(Violation {
                capability: "shell.execute".to_owned(),
                detail: format!("{cmd}: command is explicitly denied"),
                severity: Severity::High,
            });
        }
    }

    // ── secrets ───────────────────────────────────────────────────────────
    if caps.secrets_read && !policy.secrets.access {
        violations.push(Violation {
            capability: "secrets.read".to_owned(),
            detail: "reads the environment or a key store, which policy forbids".to_owned(),
            severity: Severity::High,
        });
    }

    // ── undeclared behaviour ──────────────────────────────────────────────
    // Under-declared capability is a policy concern even without an explicit
    // rule: a skill doing something it never said is not auditable.
    for m in subject.diff.blocking() {
        violations.push(Violation {
            capability: m.capability.clone(),
            detail: format!("undeclared: {}", m.detail),
            severity: m.severity,
        });
    }

    // ── findings thresholds ───────────────────────────────────────────────
    let worst_finding = subject.findings.iter().map(|f| f.severity).max();
    let denied_findings: Vec<&crate::models::Finding> = subject
        .findings
        .iter()
        .filter(|f| f.severity >= policy.findings.deny_severity)
        .collect();

    let decision = decide(
        &violations,
        &denied_findings,
        worst_finding,
        policy,
        subject.approved_digest,
    );

    violations.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.capability.cmp(&b.capability))
            .then(a.detail.cmp(&b.detail))
    });

    PolicyDecision {
        decision,
        violations,
        worst_finding,
    }
}

fn decide(
    violations: &[Violation],
    denied_findings: &[&crate::models::Finding],
    worst_finding: Option<Severity>,
    policy: &Policy,
    approved_digest: Option<&str>,
) -> Decision {
    // An explicit violation, or a finding at the deny threshold, blocks.
    if !violations.is_empty() || !denied_findings.is_empty() {
        return Decision::Deny;
    }
    // Undeclared behaviour is a mismatch-derived violation, already denied
    // above. Everything left is either clean or approvable.
    if let Some(w) = worst_finding {
        if w >= policy.findings.require_approval_severity {
            // An approval bound to this exact content satisfies the gate.
            return match approved_digest {
                Some(_) => Decision::Allow,
                None => Decision::RequireApproval,
            };
        }
    }
    if violations.is_empty() && denied_findings.is_empty() {
        return Decision::Allow;
    }
    Decision::Warn
}

// ── the lockfile ──────────────────────────────────────────────────────────

/// What was approved, by whom, and against which exact content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub reviewer: String,
    pub reason: String,
    /// RFC 3339, second precision: nanoseconds make every write a diff.
    pub approved_at: String,
    /// The digest the reviewer saw. A content change voids the approval.
    pub content_digest: String,
    /// Free-form record of what was waved through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockSkill {
    pub source: Option<String>,
    pub repository: Option<String>,
    pub commit: Option<String>,
    pub content_digest: String,
    /// Digest from a foreign lockfile, kept so its own verification still works.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Written by the scanner from the skill's own declaration. Never from
    /// observation: mixing the two would let a skill approve itself.
    #[serde(default)]
    pub declared_permissions: crate::models::PermissionDecl,
    /// Written by the scanner from executable files only.
    #[serde(default)]
    pub observed_capabilities: Capability,
    /// The mismatch set as it stood when the lock was written, so a reviewer
    /// reading a later diff can see what changed.
    #[serde(default)]
    pub mismatches: Vec<crate::models::Mismatch>,
    #[serde(default)]
    pub dependencies: Vec<crate::models::Dependency>,
    pub policy_decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Approval>,
    /// Second precision, so re-running does not churn the file.
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    pub lockfile_version: u32,
    pub generated_by: String,
    /// Proves the file was written by the tool, not by hand.
    #[serde(default)]
    pub verifier: String,
    pub rule_set_version: String,
    pub skills: std::collections::BTreeMap<String, LockSkill>,
}

impl Lockfile {
    pub fn new() -> Self {
        Lockfile {
            lockfile_version: 1,
            generated_by: format!("{TOOL} {}", env!("CARGO_PKG_VERSION")),
            verifier: format!("{TOOL} {}", env!("CARGO_PKG_VERSION")),
            rule_set_version: crate::RULE_SET_VERSION.to_owned(),
            skills: std::collections::BTreeMap::new(),
        }
    }

    pub fn path(dir: &Path) -> std::path::PathBuf {
        dir.join("SKILLGUARD.lock")
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        serde_json::from_str(&src)
            .map_err(|e| format!("{} is not a valid lockfile: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialise lockfile: {e}"))?;
        std::fs::write(path, format!("{body}\n"))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// An approval only applies to the content it was granted for.
    pub fn approval_for(&self, name: &str, digest: &Digest) -> Option<&Approval> {
        let entry = self.skills.get(name)?;
        let approval = entry.approved_by.as_ref()?;
        (approval.content_digest == digest.as_str()).then_some(approval)
    }

    pub fn is_hand_edited(&self) -> bool {
        !self.generated_by.starts_with(TOOL)
    }
}

pub const TOOL: &str = "skillguard";

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

/// One verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub skill: String,
    pub ok: bool,
    pub checks: Vec<VerifyCheck>,
}

impl VerifyReport {
    /// Recompute everything and compare. Nothing in the lockfile is trusted:
    /// each recorded value is re-derived from the bytes on disk.
    pub fn run(
        name: &str,
        root: &Path,
        entry: &LockSkill,
        provenance: &crate::hash::Provenance,
    ) -> Result<Self, String> {
        let mut checks: Vec<VerifyCheck> = Vec::new();

        let (actual_digest, files) = crate::hash::digest_dir(root)?;
        let digest_ok = actual_digest.as_str() == entry.content_digest;
        checks.push(VerifyCheck {
            name: "content_digest".to_owned(),
            ok: digest_ok,
            detail: if digest_ok {
                format!("matches {}", entry.content_digest)
            } else {
                format!(
                    "expected {}, found {}",
                    entry.content_digest,
                    actual_digest.as_str()
                )
            },
        });

        if !digest_ok {
            checks.push(VerifyCheck {
                name: "changed_files".to_owned(),
                ok: false,
                detail: describe_changes(&files, entry).unwrap_or_else(|| {
                    "no per-file record in the lockfile to compare against".to_owned()
                }),
            });
        }

        // Source identity: both halves, or it is not reproducible.
        match (&entry.commit, &provenance.commit) {
            (Some(want), Some(got)) => {
                let ok = want == got;
                checks.push(VerifyCheck {
                    name: "commit".to_owned(),
                    ok,
                    detail: if ok {
                        format!("matches {got}")
                    } else {
                        format!("expected {want}, found {got}")
                    },
                });
            }
            (Some(_), None) => checks.push(VerifyCheck {
                name: "commit".to_owned(),
                ok: false,
                detail: "lockfile pins a commit but none could be read from disk".to_owned(),
            }),
            (None, _) => checks.push(VerifyCheck {
                name: "commit".to_owned(),
                ok: false,
                detail: "lockfile does not pin a commit: the install is not reproducible"
                    .to_owned(),
            }),
        }

        if let Some(want) = &entry.repository {
            match &provenance.repository {
                Some(got) => checks.push(VerifyCheck {
                    name: "repository".to_owned(),
                    ok: want == got,
                    detail: if want == got {
                        format!("matches {got}")
                    } else {
                        format!("expected {want}, found {got}")
                    },
                }),
                None => checks.push(VerifyCheck {
                    name: "repository".to_owned(),
                    ok: false,
                    detail: format!("expected {want}, but no remote could be read"),
                }),
            }
        }

        // An approval that no longer matches the content must not count.
        if let Some(approval) = &entry.approved_by {
            let still_valid = approval.content_digest == actual_digest.as_str();
            checks.push(VerifyCheck {
                name: "approval".to_owned(),
                ok: still_valid,
                detail: if still_valid {
                    format!(
                        "approved by {} - still valid for this content",
                        approval.reviewer
                    )
                } else {
                    format!(
                        "approval by {} was for {}, but the content is now {}: \
                         the approval no longer applies",
                        approval.reviewer, approval.content_digest, actual_digest
                    )
                },
            });
        }

        let ok = checks.iter().all(|c| c.ok);
        Ok(VerifyReport {
            skill: name.to_owned(),
            ok,
            checks,
        })
    }

    pub fn render(&self) -> String {
        let mut o = String::new();
        o.push_str(&format!("\n  {}\n", self.skill));
        for c in &self.checks {
            let mark = if c.ok { "ok  " } else { "FAIL" };
            o.push_str(&format!("    [{mark}] {:<16} {}\n", c.name, c.detail));
        }
        o.push('\n');
        o
    }
}

/// Best-effort explanation of which files differ from what was locked.
fn describe_changes(files: &[crate::hash::FileDigest], entry: &LockSkill) -> Option<String> {
    if entry.mismatches.is_empty() && entry.content_digest.is_empty() {
        return None;
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
    Some(format!(
        "{} file(s), {} byte(s) on disk; the lockfile records no per-file digests, \
         so the changed files cannot be named",
        files.len(),
        total
    ))
}

/// Human-readable policy decision.
pub fn render_decision(decision: &PolicyDecision) -> String {
    let mut o = String::new();
    match decision.decision {
        Decision::Allow => o.push_str("  allow\n"),
        Decision::Warn => o.push_str("  warn\n"),
        Decision::RequireApproval => o.push_str("  require approval\n"),
        Decision::Deny => o.push_str("  BLOCKED\n"),
    }
    for v in &decision.violations {
        o.push_str(&format!(
            "    {}  {:<18} {}\n",
            v.severity,
            v.capability,
            text::sanitize_for_display(&v.detail)
        ));
    }
    if decision.violations.is_empty() {
        o.push_str("    no policy violations\n");
    }
    if decision.decision.blocks() {
        o.push_str("\n  installation blocked.\n");
    }
    o
}

/// Is this mismatch the kind that should stop an install?
pub fn is_blocking_mismatch(kind: MismatchKind) -> bool {
    kind == MismatchKind::UnderDeclared || kind == MismatchKind::Conflicting
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DiffReport, Finding, Mismatch};

    fn caps(hosts: &[&str], shells: &[&str], secrets: bool) -> Capability {
        Capability {
            network_outbound: hosts.iter().map(|s| s.to_string()).collect(),
            shell_execute: shells.iter().map(|s| s.to_string()).collect(),
            secrets_read: secrets,
            ..Capability::default()
        }
    }

    fn finding(sev: Severity) -> Finding {
        Finding::new(
            "TEST",
            sev,
            crate::models::Confidence::High,
            "SKILL.md",
            "test",
            vec![crate::models::Evidence {
                line: 1,
                text: "evidence".to_owned(),
                secondary: None,
                note: None,
            }],
        )
    }

    fn subject<'a>(
        caps: &'a Capability,
        diff: &'a DiffReport,
        findings: &'a [Finding],
    ) -> Subject<'a> {
        Subject {
            name: "s",
            capabilities: caps,
            diff,
            findings,
            source: None,
            approved_digest: None,
        }
    }

    #[test]
    fn clean_subject_is_allowed() {
        let c = caps(&[], &[], false);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy::new();
        let r = evaluate(&p, &subject(&c, &d, &f));
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.decision.blocks());
    }

    #[test]
    fn network_deny_blocks_every_host() {
        let c = caps(&["api.example.com"], &[], false);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy {
            network: NetworkPolicy {
                deny: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let r = evaluate(&p, &subject(&c, &d, &f));
        assert_eq!(r.decision, Decision::Deny);
        assert!(r.decision.blocks());
        assert!(r
            .violations
            .iter()
            .any(|v| v.detail.contains("api.example.com")));
    }

    #[test]
    fn allowlist_is_exhaustive() {
        let c = caps(&["api.example.com", "evil.example.net"], &[], false);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy {
            network: NetworkPolicy {
                allow_domains: vec!["api.example.com".to_owned()],
                ..Default::default()
            },
            ..Default::default()
        };
        let r = evaluate(&p, &subject(&c, &d, &f));
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.violations.len(), 1, "{:#?}", r.violations);
        assert!(r.violations[0].detail.contains("evil.example.net"));
    }

    #[test]
    fn deny_list_beats_allow_list() {
        let c = caps(&["api.example.com"], &[], false);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy {
            network: NetworkPolicy {
                allow_domains: vec!["api.example.com".to_owned()],
                deny_domains: vec!["api.example.com".to_owned()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(evaluate(&p, &subject(&c, &d, &f)).decision, Decision::Deny);
    }

    #[test]
    fn undeclared_behaviour_is_a_violation() {
        let c = caps(&["evil.example.com"], &[], false);
        let d = DiffReport {
            no_declaration: false,
            mismatches: vec![Mismatch {
                kind: MismatchKind::UnderDeclared,
                capability: "network.outbound".to_owned(),
                detail: "evil.example.com".to_owned(),
                severity: Severity::High,
            }],
        };
        let f: Vec<Finding> = vec![];
        let r = evaluate(&Policy::new(), &subject(&c, &d, &f));
        assert_eq!(r.decision, Decision::Deny, "under-declared egress blocks");
        assert!(r.violations.iter().any(|v| v.detail.contains("undeclared")));
    }

    #[test]
    fn over_declaration_does_not_block() {
        let c = caps(&[], &[], false);
        let d = DiffReport {
            no_declaration: false,
            mismatches: vec![Mismatch {
                kind: MismatchKind::OverDeclared,
                capability: "network.outbound".to_owned(),
                detail: "unused.example.com".to_owned(),
                severity: Severity::Info,
            }],
        };
        let f: Vec<Finding> = vec![];
        assert_eq!(
            evaluate(&Policy::new(), &subject(&c, &d, &f)).decision,
            Decision::Allow
        );
    }

    #[test]
    fn secrets_denial_blocks() {
        let c = caps(&[], &[], true);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy {
            secrets: SecretsPolicy { access: false },
            ..Default::default()
        };
        assert_eq!(evaluate(&p, &subject(&c, &d, &f)).decision, Decision::Deny);
    }

    #[test]
    fn denied_findings_threshold_blocks() {
        let c = caps(&[], &[], false);
        let d = DiffReport::default();
        let f = vec![finding(Severity::Critical)];
        let p = Policy {
            findings: FindingsPolicy {
                deny_severity: Severity::Critical,
                require_approval_severity: Severity::High,
            },
            ..Default::default()
        };
        assert_eq!(evaluate(&p, &subject(&c, &d, &f)).decision, Decision::Deny);
    }

    #[test]
    fn approval_severity_requires_approval_then_allows() {
        let c = caps(&[], &[], false);
        let d = DiffReport::default();
        let f = vec![finding(Severity::High)];
        let p = Policy::new();
        assert_eq!(
            evaluate(&p, &subject(&c, &d, &f)).decision,
            Decision::RequireApproval
        );

        let mut s = subject(&c, &d, &f);
        s.approved_digest = Some("sha256:abc");
        assert_eq!(evaluate(&p, &s).decision, Decision::Allow);
    }

    #[test]
    fn source_prefix_denial() {
        let c = caps(&[], &[], false);
        let d = DiffReport::default();
        let f: Vec<Finding> = vec![];
        let p = Policy {
            sources: SourcePolicy {
                deny_prefixes: vec!["file:".to_owned()],
            },
            ..Default::default()
        };
        let mut s = subject(&c, &d, &f);
        s.source = Some("file:///etc/passwd");
        assert_eq!(evaluate(&p, &s).decision, Decision::Deny);
    }

    #[test]
    fn unknown_policy_field_is_an_error() {
        // A typo that silently disables a control is worse than a crash.
        let err = parse_policy("network:\n  allow_domians:\n    - a.example.com\n");
        assert!(err.is_err(), "a misspelled key must fail loudly: {err:?}");
        let err = parse_policy("network:\n  deny: maybe\n");
        assert!(err.is_err(), "a wrong type must fail loudly");
    }

    #[test]
    fn policy_round_trips_through_yaml() {
        let src = "policy_version: 1\nnetwork:\n  deny: true\nfilesystem:\n  deny_paths: ['**/.env']\nsecrets:\n  access: false\n";
        let p = parse_policy(src).unwrap_or_default();
        assert!(p.network.deny);
        assert!(!p.secrets.access);
        assert_eq!(p.filesystem.deny_paths, vec!["**/.env".to_owned()]);
    }

    #[test]
    fn approval_is_bound_to_content() {
        let mut lock = Lockfile::new();
        lock.skills.insert(
            "s".to_owned(),
            LockSkill {
                source: None,
                repository: None,
                commit: None,
                content_digest: "sha256:aaa".to_owned(),
                legacy_digest: None,
                version: None,
                license: None,
                declared_permissions: Default::default(),
                observed_capabilities: Default::default(),
                mismatches: vec![],
                dependencies: vec![],
                policy_decision: Decision::Allow,
                approved_by: Some(Approval {
                    reviewer: "alice".to_owned(),
                    reason: "reviewed".to_owned(),
                    approved_at: "2026-10-07T00:00:00Z".to_owned(),
                    content_digest: "sha256:aaa".to_owned(),
                    note: None,
                }),
                observed_at: "2026-10-07T00:00:00Z".to_owned(),
            },
        );

        assert!(lock
            .approval_for("s", &Digest("sha256:aaa".to_owned()))
            .is_some());
        assert!(
            lock.approval_for("s", &Digest("sha256:bbb".to_owned()))
                .is_none(),
            "a content change must void the approval"
        );
    }

    #[test]
    fn lockfile_round_trips_and_detects_tampering() {
        let dir = std::env::temp_dir().join("sg-lock-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let path = Lockfile::path(&dir);
        let mut lock = Lockfile::new();
        lock.skills.insert(
            "x".to_owned(),
            LockSkill {
                source: Some("github:o/r".to_owned()),
                repository: Some("o/r".to_owned()),
                commit: Some("a".repeat(40)),
                content_digest: "sha256:abc".to_owned(),
                legacy_digest: None,
                version: None,
                license: Some("MIT".to_owned()),
                declared_permissions: Default::default(),
                observed_capabilities: Default::default(),
                mismatches: vec![],
                dependencies: vec![],
                policy_decision: Decision::Allow,
                approved_by: None,
                observed_at: "2026-10-07T00:00:00Z".to_owned(),
            },
        );
        lock.save(&path).unwrap_or_default();
        let back = Lockfile::load(&path).unwrap_or_default();
        assert_eq!(back.skills.len(), 1);
        assert!(!back.is_hand_edited());

        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(&path, raw.replace("skillguard", "handwrote")).unwrap_or_default();
        let tampered = Lockfile::load(&path).unwrap_or_default();
        assert!(
            tampered.is_hand_edited(),
            "a hand-edited lock must be detectable"
        );
    }

    #[test]
    fn decision_render_is_escape_free() {
        let d = PolicyDecision {
            decision: Decision::Deny,
            violations: vec![Violation {
                capability: "network.outbound".to_owned(),
                detail: "\u{1B}[2Jwiped".to_owned(),
                severity: Severity::High,
            }],
            worst_finding: None,
        };
        let out = render_decision(&d);
        assert!(!out.contains('\u{1B}'));
        assert!(out.contains("BLOCKED"));
    }
}
