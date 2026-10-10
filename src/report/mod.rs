//! Report rendering.
//!
//! Four formats, one rule: **every finding carries its evidence**. The text
//! renderer is the primary product surface; JSON is for tooling; SARIF is for
//! GitHub Code Scanning; Markdown is for PR comments.

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod text;

use crate::models::{Confidence, Finding, Severity, SkippedFile};
use crate::scan::ScanOutcome;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub use json::to_json;
pub use markdown::to_markdown;
pub use sarif::to_sarif;
pub use text::{to_text, to_text_with};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
    Markdown,
}

/// One skill's complete result, as emitted to every renderer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillReport {
    pub name: String,
    /// Where the skill lives, relative to the working directory, with forward
    /// slashes. `None` when it is the working directory itself or cannot be
    /// expressed relative to it. SARIF needs this to point at the right file:
    /// every `Finding::file` is relative to the *skill*, not the repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub rule_set_version: String,
    pub description: Option<String>,
    pub declared_permissions_raw: Option<String>,
    pub license_declared: Option<String>,
    pub license_file_found: bool,
    pub capabilities: crate::models::Capability,
    pub dependencies: Vec<crate::models::Dependency>,
    pub counts: Counts,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
    /// What prompt-injection detection does and does not cover (issue #8).
    #[serde(default)]
    pub injection: InjectionCoverage,
}

/// The honest coverage note for prompt-injection detection.
///
/// Snyk attributes 91% of confirmed malicious skills to prompt injection, and
/// SkillGuard's detection is a small set of regexes over normalized text. The
/// miss rate is unknown, and an unknown gap a reader cannot see is worse than a
/// bad one, because `no findings` reads as `no injection`. This travels with
/// every skill report so that inference is never available (issue #8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionCoverage {
    /// How detection is performed, so the reader can judge it.
    pub method: String,
    /// Always false, and kept explicit so nothing can quietly flip it.
    pub detection_is_complete: bool,
    /// Number of `PI_*` findings in this skill.
    pub findings: usize,
    pub caveat: String,
}

pub const INJECTION_METHOD: &str = "deterministic regular expressions over normalized text";
pub const INJECTION_CAVEAT: &str = "prompt-injection detection is heuristic and incomplete: it matches known phrasings, not intent. A clean scan is not proof that a skill is free of injection; the miss rate is unmeasured (issue #8)";

impl InjectionCoverage {
    pub fn of(findings: &[Finding]) -> Self {
        InjectionCoverage {
            method: INJECTION_METHOD.to_owned(),
            detection_is_complete: false,
            findings: findings
                .iter()
                .filter(|f| f.rule.as_str().starts_with("PI_"))
                .count(),
            caveat: INJECTION_CAVEAT.to_owned(),
        }
    }
}

impl Default for InjectionCoverage {
    fn default() -> Self {
        Self::of(&[])
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl Counts {
    pub fn of(findings: &[Finding]) -> Counts {
        let mut c = Counts::default();
        for f in findings {
            match f.severity {
                Severity::Info => c.info += 1,
                Severity::Low => c.low += 1,
                Severity::Medium => c.medium += 1,
                Severity::High => c.high += 1,
                Severity::Critical => c.critical += 1,
            }
        }
        c
    }

    pub fn total(&self) -> usize {
        self.info + self.low + self.medium + self.high + self.critical
    }

    /// The highest severity present, or `None` when clean.
    pub fn max_severity(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else if self.info > 0 {
            Some(Severity::Info)
        } else {
            None
        }
    }
}

/// A full run over one or more skills.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub tool_version: String,
    pub rule_set_version: String,
    pub skills: Vec<SkillReport>,
    pub totals: Counts,
}

pub const TOOL: &str = "skillguard";

impl SkillReport {
    pub fn from_outcome(out: &ScanOutcome) -> SkillReport {
        SkillReport {
            name: out.skill_name.clone(),
            source_path: out.root.as_deref().and_then(source_prefix),
            rule_set_version: crate::RULE_SET_VERSION.to_owned(),
            description: out.description.clone(),
            declared_permissions_raw: out.declared_permissions_raw.clone(),
            license_declared: out.license_declared.clone(),
            license_file_found: out.license_file_found,
            capabilities: out.capabilities.clone(),
            dependencies: out.dependencies.clone(),
            counts: Counts::of(&out.findings),
            injection: InjectionCoverage::of(&out.findings),
            findings: out.findings.clone(),
            skipped: out.skipped.clone(),
        }
    }
}

/// Repository-relative, slash-separated prefix for a skill's own files.
///
/// `Finding::file` is relative to the *skill* directory (`scripts/run.sh`), but
/// a SARIF consumer resolves `artifactLocation.uri` against the *repository*
/// root. Without this prefix, a skill vendored at `skills/foo/` would annotate
/// `scripts/run.sh` — a file that may not exist, or worse, a different one.
///
/// Returns `None` when there is nothing safe to prefix: the working directory
/// itself, an absolute path outside it, or anything containing `..`.
fn source_prefix(root: &Path) -> Option<String> {
    let relative = if root.is_absolute() {
        // An absolute path outside the working directory has no
        // repository-relative form. Emitting it would leak the machine's layout
        // and is not a location Code Scanning can use.
        root.strip_prefix(std::env::current_dir().ok()?).ok()?
    } else {
        root
    };

    let mut parts: Vec<String> = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(s) => parts.push(s.to_string_lossy().to_string()),
            // `..`, a root, or a Windows prefix: not expressible as a
            // repository-relative URI, so do not pretend otherwise.
            _ => return None,
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

impl Report {
    pub fn new(skills: Vec<SkillReport>) -> Report {
        let mut totals = Counts::default();
        for s in &skills {
            totals.info += s.counts.info;
            totals.low += s.counts.low;
            totals.medium += s.counts.medium;
            totals.high += s.counts.high;
            totals.critical += s.counts.critical;
        }
        Report {
            tool: TOOL.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            rule_set_version: crate::RULE_SET_VERSION.to_owned(),
            skills,
            totals,
        }
    }

    /// Overall verdict: the worst severity across every skill.
    pub fn verdict(&self) -> Option<Severity> {
        self.totals.max_severity()
    }

    /// All findings across all skills, flattened.
    pub fn all_findings(&self) -> Vec<(&str, &Finding)> {
        self.skills
            .iter()
            .flat_map(|s| s.findings.iter().map(move |f| (s.name.as_str(), f)))
            .collect()
    }

    /// Findings at or above `sev`.
    pub fn findings_at_or_above(&self, sev: Severity) -> Vec<(&str, &Finding)> {
        self.all_findings()
            .into_iter()
            .filter(|(_, f)| f.severity >= sev)
            .collect()
    }

    /// How many findings rest on analyst-grade evidence rather than a hint.
    pub fn high_confidence_count(&self) -> usize {
        self.all_findings()
            .iter()
            .filter(|(_, f)| f.confidence == Confidence::High)
            .count()
    }

    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Text => to_text(self),
            Format::Json => to_json(self),
            Format::Sarif => to_sarif(self),
            Format::Markdown => to_markdown(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Evidence, RuleId};

    #[test]
    fn source_prefix_normalises_and_rejects() {
        // Leading `./` from walking `.` must not reach the URI.
        assert_eq!(
            source_prefix(Path::new("./skills/foo")),
            Some("skills/foo".to_owned())
        );
        assert_eq!(
            source_prefix(Path::new("skills/foo")),
            Some("skills/foo".to_owned())
        );
        // Nothing to prefix for the repository root itself.
        assert_eq!(source_prefix(Path::new(".")), None);
        assert_eq!(source_prefix(Path::new("")), None);
        // Never emit a URI that escapes the repository.
        assert_eq!(source_prefix(Path::new("../outside")), None);
    }

    fn finding(sev: Severity) -> Finding {
        Finding::new(
            RuleId::from("TEST_RULE"),
            sev,
            Confidence::High,
            "SKILL.md",
            "test",
            vec![Evidence {
                line: 1,
                text: "evidence".to_owned(),
                secondary: None,
                note: None,
            }],
        )
    }

    fn skill_report(f: Finding) -> SkillReport {
        SkillReport {
            name: "a".into(),
            source_path: None,
            rule_set_version: "0".into(),
            description: None,
            declared_permissions_raw: None,
            license_declared: None,
            license_file_found: false,
            capabilities: Default::default(),
            dependencies: vec![],
            counts: Counts::of(std::slice::from_ref(&f)),
            injection: InjectionCoverage::of(std::slice::from_ref(&f)),
            findings: vec![f],
            skipped: vec![],
        }
    }

    #[test]
    fn counts_and_verdict() {
        let r = Report::new(vec![skill_report(finding(Severity::Low))]);
        assert_eq!(r.totals.low, 1);
        assert_eq!(r.totals.total(), 1);
        assert_eq!(r.verdict(), Some(Severity::Low));
    }

    #[test]
    fn totals_accumulate_across_skills() {
        let r = Report::new(vec![
            skill_report(finding(Severity::Critical)),
            skill_report(finding(Severity::Info)),
        ]);
        assert_eq!(r.totals.critical, 1);
        assert_eq!(r.totals.info, 1);
        assert_eq!(r.verdict(), Some(Severity::Critical));
    }

    #[test]
    fn clean_report_has_no_verdict() {
        let r = Report::new(vec![]);
        assert_eq!(r.verdict(), None);
        assert!(r.all_findings().is_empty());
    }

    #[test]
    fn filtering_by_threshold() {
        let r = Report::new(vec![skill_report(finding(Severity::Medium))]);
        assert_eq!(r.findings_at_or_above(Severity::High).len(), 0);
        assert_eq!(r.findings_at_or_above(Severity::Medium).len(), 1);
    }
}
