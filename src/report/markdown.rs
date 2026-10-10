//! Markdown output, aimed at pull-request comments and review packets.

use crate::models::Severity;
use crate::report::Report;

pub fn to_markdown(report: &Report) -> String {
    let mut o = String::new();

    o.push_str("## SkillGuard\n\n");

    match report.verdict() {
        None => o.push_str("No findings at or above INFO.\n\n"),
        Some(sev) => {
            let badge = match sev {
                Severity::Critical | Severity::High => "**BLOCK**",
                _ => "**REVIEW**",
            };
            o.push_str(&format!(
                "{badge} - worst severity **{sev}** across {} skill(s).\n\n",
                report.skills.len()
            ));
            o.push_str("| critical | high | medium | low | info |\n");
            o.push_str("|---|---|---|---|---|\n");
            o.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n\n",
                report.totals.critical,
                report.totals.high,
                report.totals.medium,
                report.totals.low,
                report.totals.info
            ));
        }
    }

    for s in &report.skills {
        o.push_str(&format!("### `{}`\n\n", s.name));
        if let Some(d) = &s.description {
            o.push_str(&format!("{}\n\n", d));
        }

        if s.findings.is_empty() {
            o.push_str("No findings.\n\n");
        } else {
            o.push_str("| severity | rule | location | evidence |\n");
            o.push_str("|---|---|---|---|\n");
            for f in &s.findings {
                let loc = if f.primary_line() > 0 {
                    format!("`{}:{}`", f.file, f.primary_line())
                } else {
                    format!("`{}`", f.file)
                };
                let ev = f
                    .evidence
                    .first()
                    .map(|e| crate::text::truncate_chars(&e.text, 90).replace('|', "\\|"))
                    .unwrap_or_default();
                o.push_str(&format!(
                    "| {} | `{}` | {} | `{}` |\n",
                    f.severity.as_str(),
                    f.rule.as_str(),
                    loc,
                    ev
                ));
            }
            o.push('\n');
        }

        o.push_str(&capability_table(s));
    }

    o.push_str(
        "---\n\n<sub>SkillGuard is offline and deterministic: no skill content leaves this machine \
         and no language model is involved. Detection is not judgement - read the evidence before \
         acting. Rule set ",
    );
    o.push_str(&report.rule_set_version);
    o.push_str(", tool ");
    o.push_str(&report.tool_version);
    o.push_str(".</sub>\n");

    // A clean block must not read as "no prompt injection" (issue #8).
    if report.skills.iter().any(|s| s.injection.findings == 0) {
        o.push_str(&format!(
            "\n> **Coverage note:** {}.\n",
            crate::report::INJECTION_CAVEAT
        ));
    }

    o
}

fn capability_table(s: &crate::report::SkillReport) -> String {
    let c = &s.capabilities;
    if c.is_empty() {
        return String::from("No capability was observed in executable files.\n\n");
    }
    let mut o = String::from("<details><summary>observed capabilities</summary>\n\n");
    o.push_str("| capability | value |\n|---|---|\n");
    if !c.network_outbound.is_empty() {
        o.push_str(&format!(
            "| network.outbound | {} |\n",
            c.network_outbound.join(", ")
        ));
    }
    if !c.shell_execute.is_empty() {
        o.push_str(&format!(
            "| shell.execute | {} |\n",
            c.shell_execute.join(", ")
        ));
    }
    if !c.filesystem_read.is_empty() {
        o.push_str(&format!(
            "| filesystem.read | {} |\n",
            c.filesystem_read.join(", ")
        ));
    }
    if !c.filesystem_write.is_empty() {
        o.push_str(&format!(
            "| filesystem.write | {} |\n",
            c.filesystem_write.join(", ")
        ));
    }
    if !c.package_install.is_empty() {
        o.push_str(&format!(
            "| package_install | {} |\n",
            c.package_install.join(", ")
        ));
    }
    if c.secrets_read {
        o.push_str("| secrets.read | true |\n");
    }
    if !s.dependencies.is_empty() {
        let deps: Vec<String> = s
            .dependencies
            .iter()
            .take(40)
            .map(|d| match &d.version_spec {
                Some(v) => format!("{}:{}", d.name, v),
                None => d.name.clone(),
            })
            .collect();
        o.push_str(&format!(
            "| dependencies ({} total) | {} |\n",
            s.dependencies.len(),
            deps.join(", ")
        ));
    }
    o.push_str("\n</details>\n\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Evidence, Finding, RuleId};
    use crate::report::{Counts, SkillReport};

    fn report() -> Report {
        let f = Finding::new(
            RuleId::from("SECRET_PRIVATE_KEY"),
            Severity::Critical,
            Confidence::High,
            "scripts/a.sh",
            "a key is embedded",
            vec![Evidence {
                line: 4,
                text: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...".into(),
                secondary: None,
                note: None,
            }],
        );
        Report::new(vec![SkillReport {
            name: "suspicious-skill".into(),
            source_path: None,
            rule_set_version: "0.1.0".into(),
            description: Some("does things".into()),
            declared_permissions_raw: None,
            license_declared: None,
            license_file_found: false,
            capabilities: Default::default(),
            dependencies: vec![],
            counts: Counts::of(std::slice::from_ref(&f)),
            injection: crate::report::InjectionCoverage::of(std::slice::from_ref(&f)),
            findings: vec![f],
            skipped: vec![],
        }])
    }

    #[test]
    fn emits_a_summary_table_and_rows() {
        let md = to_markdown(&report());
        assert!(md.starts_with("## SkillGuard"));
        assert!(md.contains("**BLOCK**"));
        assert!(md.contains("| critical | high |"));
        assert!(md.contains("`SECRET_PRIVATE_KEY`"));
        assert!(md.contains("`scripts/a.sh:4`"));
    }

    #[test]
    fn pipes_in_evidence_are_escaped() {
        let mut r = report();
        r.skills[0].findings[0].evidence[0].text = "a | b | c".into();
        let md = to_markdown(&r);
        assert!(md.contains("a \\| b \\| c"), "{md}");
    }

    #[test]
    fn clean_report_says_so() {
        let md = to_markdown(&Report::new(vec![]));
        assert!(md.contains("No findings"));
    }

    #[test]
    fn includes_the_offline_disclaimer() {
        let md = to_markdown(&report());
        assert!(md.contains("no language model"));
        assert!(md.contains("Detection is not judgement"));
    }

    #[test]
    fn capabilities_render_in_a_details_block() {
        let mut r = report();
        r.skills[0].capabilities.network_outbound = vec!["evil.example.com".into()];
        r.skills[0].capabilities.secrets_read = true;
        let md = to_markdown(&r);
        assert!(md.contains("<details>"));
        assert!(md.contains("evil.example.com"));
    }
}
