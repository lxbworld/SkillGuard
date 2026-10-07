//! Pure data types. This module must not depend on any other internal module —
//! it is the contract layer. See docs/ARCHITECTURE.md §2.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Risk level. Ordered from least to most severe so `severity >= X` works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "INFO" => Some(Severity::Info),
            "LOW" => Some(Severity::Low),
            "MEDIUM" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure we are that a finding is real. Deliberately coarse: this is not a
/// probability, and it must never be used as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Pattern matched in a documentation context; a human should look.
    Low,
    /// Pattern matched in code or a config value.
    Medium,
    /// Structural match with a corroborating signal (chain, key format, escape).
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// What kind of file a finding came from. Drives both rule matching and the
/// declared-vs-observed diff (docs references are not capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// YAML frontmatter of SKILL.md.
    Frontmatter,
    /// Prose body of SKILL.md.
    Markdown,
    /// A file under scripts/ or with an executable extension.
    Script,
    /// A dependency manifest (package.json, requirements.txt, pyproject.toml…).
    Manifest,
    /// A license, README or other metadata file.
    Metadata,
}

impl ArtifactKind {
    /// Only code counts as observed *capability*. Documentation is explanation.
    pub fn is_executable(self) -> bool {
        matches!(self, ArtifactKind::Script | ArtifactKind::Manifest)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Frontmatter => "frontmatter",
            ArtifactKind::Markdown => "markdown",
            ArtifactKind::Script => "script",
            ArtifactKind::Manifest => "manifest",
            ArtifactKind::Metadata => "metadata",
        }
    }
}

/// Stable identifier of a rule, e.g. `SECRET_PRIVATE_KEY`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl RuleId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        RuleId(s.to_owned())
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One piece of evidence. Every finding has at least one (invariant S3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// 1-based line number in the original file.
    pub line: usize,
    /// Verbatim excerpt from the original file, already sanitized for display.
    pub text: String,
    /// Secondary location, used by chain rules (the fetch source, the exec sink).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary: Option<Box<Evidence>>,
    /// Short note on how this matched, e.g. `regex`, `chain`, `structural`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A single security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Skill-relative path, forward slashes, e.g. `scripts/setup.sh`.
    pub file: String,
    pub message: String,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Set for findings produced from a normalized/derived view (obfuscation,
    /// base64 shadow text) so the reader knows the literal text is not the match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_normalization: Option<String>,
}

impl Finding {
    pub fn new(
        rule: impl Into<RuleId>,
        severity: Severity,
        confidence: Confidence,
        file: impl Into<String>,
        message: impl Into<String>,
        evidence: Vec<Evidence>,
    ) -> Self {
        Finding {
            rule: rule.into(),
            severity,
            confidence,
            file: file.into(),
            message: message.into(),
            evidence,
            capability: None,
            via_normalization: None,
        }
    }

    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capability = Some(cap.into());
        self
    }

    pub fn primary_line(&self) -> usize {
        self.evidence.first().map_or(0, |e| e.line)
    }
}

/// A single capability, as observed in code. Values are normalized and sorted
/// so that diffing and hashing are stable (invariant S4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Capability {
    /// e.g. `["api.example.com", "evil.example.com"]`
    pub network_outbound: Vec<String>,
    /// Executable basenames, e.g. `["curl", "python"]`
    pub shell_execute: Vec<String>,
    /// Filesystem paths or globs the skill touches.
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    /// `true` when the code reads process environment variables wholesale.
    pub secrets_read: bool,
    /// Package managers the skill installs from.
    pub package_install: Vec<String>,
}

impl Capability {
    pub fn is_empty(&self) -> bool {
        self.network_outbound.is_empty()
            && self.shell_execute.is_empty()
            && self.filesystem_read.is_empty()
            && self.filesystem_write.is_empty()
            && !self.secrets_read
            && self.package_install.is_empty()
    }

    /// Sort and dedup every list, so `PartialEq` reflects content, not order.
    pub fn normalized(&self) -> Capability {
        fn norm(v: &mut Vec<String>) {
            v.sort();
            v.dedup();
        }
        let mut c = self.clone();
        norm(&mut c.network_outbound);
        norm(&mut c.shell_execute);
        norm(&mut c.filesystem_read);
        norm(&mut c.filesystem_write);
        norm(&mut c.package_install);
        c
    }
}

/// Convenience alias used in reports.
pub type CapabilitySet = Capability;

/// One declared dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version_spec: Option<String>,
}

// ── Phase 2: declared permissions and the declared-vs-observed diff ────────

/// What a skill claims it needs, read from frontmatter.
///
/// Deliberately a *separate type* from [`Capability`]. Invariant S8: a declared
/// value and an observed value must never be assignable to each other, because
/// conflating them is exactly how a scanner ends up "verifying" a skill against
/// its own claims.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PermissionDecl {
    /// Hostnames the skill says it contacts.
    pub network_outbound: Vec<String>,
    /// Interpreters the skill says it runs.
    pub shell_execute: Vec<String>,
    /// Path globs the skill says it reads.
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    /// `Some(false)` is a meaningful declaration: "this skill touches no secrets".
    pub secrets_access: Option<bool>,
    /// Package managers the skill says it installs from.
    pub package_install: Vec<String>,
    /// True when the skill declared anything at all.
    pub declared: bool,
}

impl PermissionDecl {
    pub fn is_empty(&self) -> bool {
        !self.declared
            && self.network_outbound.is_empty()
            && self.shell_execute.is_empty()
            && self.filesystem_read.is_empty()
            && self.filesystem_write.is_empty()
            && self.secrets_access.is_none()
            && self.package_install.is_empty()
    }

    /// Sort, dedup and lowercase hosts, so equality reflects content.
    pub fn normalized(&self) -> PermissionDecl {
        fn norm(v: &mut Vec<String>) {
            v.sort();
            v.dedup();
        }
        let mut d = self.clone();
        norm(&mut d.network_outbound);
        norm(&mut d.shell_execute);
        norm(&mut d.filesystem_read);
        norm(&mut d.filesystem_write);
        norm(&mut d.package_install);
        d.network_outbound = d
            .network_outbound
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        d.network_outbound.sort();
        d
    }
}

/// Which side of the declared/observed line a value fell on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    /// Declared but never observed: usually harmless over-declaration.
    OverDeclared,
    /// Observed but not declared: **this is the one that blocks installs**.
    UnderDeclared,
    /// The declaration contradicts itself.
    Conflicting,
}

/// One difference between declared and observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mismatch {
    pub kind: MismatchKind,
    /// Capability path, e.g. `network.outbound`.
    pub capability: String,
    /// The value that is unaccounted for.
    pub detail: String,
    pub severity: Severity,
}

/// The result of comparing a declaration against observation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    /// No declaration was present, so no diff is possible.
    pub no_declaration: bool,
    pub mismatches: Vec<Mismatch>,
}

impl DiffReport {
    /// Mismatches that should block an install.
    pub fn blocking(&self) -> Vec<&Mismatch> {
        self.mismatches
            .iter()
            .filter(|m| m.kind == MismatchKind::UnderDeclared)
            .collect()
    }

    pub fn worst(&self) -> Option<Severity> {
        self.mismatches.iter().map(|m| m.severity).max()
    }
}

/// A file read from the skill tree.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Skill-relative path, forward slashes.
    pub rel: String,
    pub kind: ArtifactKind,
    pub bytes: Vec<u8>,
    /// False when the file was skipped (too large, binary, unreadable).
    pub scanned: bool,
    pub note: Option<String>,
}

/// Everything we know about one skill directory.
#[derive(Debug, Clone)]
pub struct Skill {
    /// Directory name.
    pub name: String,
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
    /// Raw frontmatter key/value pairs, values already stringified.
    pub frontmatter: Vec<(String, String)>,
    /// The `description:` value, used by description/behaviour mismatch.
    pub description: Option<String>,
    /// Observed capabilities, derived from executable artifacts only.
    pub capabilities: Capability,
    pub dependencies: Vec<Dependency>,
    /// Declared `permissions` block, verbatim keys. Phase 2 parses its shape;
    /// Phase 1 only records that it exists and re-scans it as text.
    pub declared_permissions_raw: Option<String>,
    pub license_declared: Option<String>,
    pub license_file_found: bool,
    /// Frontmatter could not be parsed. Reported, never silently dropped.
    pub parse_error: Option<String>,
}

/// Result of scanning one skill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSkill {
    pub name: String,
    pub findings: Vec<Finding>,
    /// Paths that were present but not scanned, with the reason.
    pub skipped: Vec<SkippedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedFile {
    pub file: String,
    pub reason: String,
}

impl Skill {
    pub fn has_executable_artifacts(&self) -> bool {
        self.files.iter().any(|f| f.kind.is_executable())
    }
}
