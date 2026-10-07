//! SkillGuard — offline, deterministic verification layer for AI Agent Skills.
//!
//! # Safety invariants (enforced; see docs/THREAT_MODEL.md §7)
//!
//! * S1 — this crate never executes scanned content, never opens a socket,
//!   and never reads credentials from the environment.
//! * S3 — every [`Finding`](models::Finding) carries a file, a line and the
//!   original evidence text. No evidence, no finding.
//! * S5 — every string rendered to a terminal passes through
//!   [`text::sanitize_for_display`](text::sanitize_for_display).
//! * S6 — every path read from a skill goes through
//!   [`walk::resolve_safe_path`](walk::resolve_safe_path).
//! * S7 — no input causes a panic. Parse failures degrade to findings.
//!
//! `unwrap`, `expect` and `panic` are denied outside tests: they are the three
//! ways a "total" function quietly becomes partial. The one deliberate
//! exception is a malformed *built-in* regex, which is a bug in this binary
//! rather than untrusted input, and must fail loudly on first use.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod capability;
pub mod hash;
pub mod import;
pub mod models;
pub mod parser;
pub mod permissions;
pub mod policy;
pub mod report;
pub mod scan;
pub mod text;
pub mod walk;

pub use models::{
    Capability, CapabilitySet, Confidence, DiffReport, Finding, Mismatch, MismatchKind,
    ParsedSkill, PermissionDecl, RuleId, Severity, Skill,
};

/// Version of the scanner rule set. Bumping this invalidates cached findings,
/// so it is recorded in every scan report and in the corpus manifest.
pub const RULE_SET_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit codes. Kept small and stable: CI systems depend on them.
pub mod exit {
    /// Scan completed, nothing blocked it.
    pub const OK: i32 = 0;
    /// Policy violation, or findings at/above `--fail-on`.
    pub const FINDINGS: i32 = 1;
    /// Integrity failure (digest or commit mismatch).
    pub const INTEGRITY: i32 = 2;
    /// Usage error.
    pub const USAGE: i32 = 3;
}
