//! Fixture-driven regression tests.
//!
//! The contract from docs/MVP.md §3: every malicious fixture must trip its
//! declared rules, every safe fixture must be quiet, and no input may panic.
//!
//! Fixtures under `tests/fixtures/` are **never executed** by the test suite.
//! They are read as bytes, exactly as a real scan would read them.

use skillguard::models::Severity;
use skillguard::scan::scan_skill;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn fixtures(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(sub)
}

fn scan_fixture(sub: &str, name: &str) -> skillguard::scan::ScanOutcome {
    let dir = fixtures(sub).join(name);
    assert!(
        dir.join("SKILL.md").exists(),
        "fixture {sub}/{name} must contain a SKILL.md"
    );
    scan_skill(&dir)
}

fn rules(out: &skillguard::scan::ScanOutcome) -> BTreeSet<String> {
    out.findings.iter().map(|f| f.rule.0.clone()).collect()
}

fn assert_trips(out: &skillguard::scan::ScanOutcome, expected: &[&str]) {
    let hit = rules(out);
    let missing: Vec<&str> = expected
        .iter()
        .filter(|e| !hit.contains(**e))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "{} did not trip {:?}\n  got: {:?}\n  all: {:#?}",
        out.skill_name,
        missing,
        hit,
        out.findings
    );
}

// ---------------------------------------------------------------------------
// safe: must be quiet
// ---------------------------------------------------------------------------

#[test]
fn safe_fixtures_produce_no_medium_or_worse() {
    {
        let out = scan_fixture("safe", "table-formatter");
        let noisy: Vec<String> = out
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .map(|f| format!("{} {}:{} {}", f.rule, f.file, f.primary_line(), f.message))
            .collect();
        assert!(
            noisy.is_empty(),
            "{} should be clean but reported: {noisy:#?}",
            out.skill_name
        );
    }
}

#[test]
fn prose_mentioning_dangerous_things_is_not_a_finding() {
    // A how-to guide that mentions `~/.ssh`, `.git-credentials` and `curl` must
    // not read like an attack. This is the false-positive guard that keeps the
    // tool usable on real skills.
    let out = scan_fixture("safe", "doc-only-guide");
    assert_trips(&out, &[]);
    assert!(
        out.capabilities.is_empty(),
        "documentation is explanation, not capability: {:#?}",
        out.capabilities
    );
    for f in &out.findings {
        assert!(
            f.severity <= Severity::Low,
            "docs-only hits must stay informational, got {} on {}",
            f.severity,
            f.rule
        );
    }
}

#[test]
fn safe_fixture_capabilities_are_empty() {
    let out = scan_fixture("safe", "table-formatter");
    assert!(
        out.capabilities.network_outbound.is_empty(),
        "{:#?}",
        out.capabilities
    );
    assert!(out.capabilities.package_install.is_empty());
    assert!(!out.capabilities.secrets_read);
    assert_eq!(out.license_declared.as_deref(), Some("MIT"));
    assert!(out.license_file_found);
}

// ---------------------------------------------------------------------------
// malicious: must trip the declared rules
// ---------------------------------------------------------------------------

#[test]
fn credential_stealer_is_caught() {
    let out = scan_fixture("malicious", "credential-stealer");
    assert_trips(
        &out,
        &[
            "SECRET_ENV_DUMP",
            "SECRET_PATH_READ",
            "NET_FETCH_CALL",
            "NET_DOMAIN_LITERAL",
            "PI_DESCRIPTION_MISMATCH",
        ],
    );
    assert!(
        out.capabilities.secrets_read,
        "the capability diff must see the credential access"
    );
    assert!(
        out.capabilities
            .network_outbound
            .iter()
            .any(|h| h.contains("telemetry-sync.example.com")),
        "{:#?}",
        out.capabilities.network_outbound
    );
}

#[test]
fn download_to_execute_is_caught() {
    let out = scan_fixture("malicious", "download-execute");
    assert_trips(
        &out,
        &[
            "DL_PIPE_TO_SHELL",
            "DL_CHAIN_FETCH_EXECUTE",
            "NET_HTTP_CLIENT",
            "SHELL_PRIVILEGE_ESCALATION",
            "PERSIST_CRON",
            "PI_INJECTION_OVERRIDE",
            "PI_CONCEALMENT",
        ],
    );
    assert!(
        out.findings
            .iter()
            .any(|f| f.severity == Severity::Critical),
        "download-to-execute is critical"
    );
}

#[test]
fn chain_finding_carries_both_ends_of_the_chain() {
    let out = scan_fixture("malicious", "download-execute");
    let chain = out
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "DL_CHAIN_FETCH_EXECUTE")
        .expect("chain finding");
    assert_eq!(chain.evidence.len(), 2, "fetch source and exec sink");
    assert!(chain.evidence[1]
        .note
        .as_deref()
        .unwrap_or("")
        .contains("sink"));
    assert!(
        chain.primary_line() < chain.evidence[1].line,
        "the fetch must be reported before the sink"
    );
}

#[test]
fn persistence_is_caught() {
    let out = scan_fixture("malicious", "persistence");
    assert_trips(
        &out,
        &[
            "PERSIST_AGENT_CONFIG",
            "PERSIST_SHELL_RC",
            "PERSIST_HOOK",
            "SHELL_DESTRUCTIVE",
        ],
    );
    let hook = out
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "PERSIST_HOOK")
        .expect("hook finding");
    assert!(
        hook.severity >= Severity::High,
        "a hook is the strongest persistence primitive available"
    );
}

#[test]
fn hardcoded_keys_are_caught_case_sensitively() {
    // AWS keys, GitHub PATs and Slack tokens only match in their canonical
    // case. If the scanner lowercases its haystack first, this test is what
    // catches the regression.
    let out = scan_fixture("malicious", "hardcoded-keys");
    assert_trips(
        &out,
        &[
            "SECRET_AWS_ACCESS_KEY",
            "SECRET_GITHUB_TOKEN",
            "SECRET_PROVIDER_TOKEN",
            "SECRET_GENERIC_ASSIGN",
        ],
    );
}

// ---------------------------------------------------------------------------
// suspicious: reported, evidence first
// ---------------------------------------------------------------------------

#[test]
fn undeclared_network_access_is_caught() {
    let out = scan_fixture("suspicious", "undeclared-network");
    assert_trips(&out, &["NET_FETCH_CALL", "NET_DYNAMIC_URL"]);
    assert!(
        out.declared_permissions_raw.is_none(),
        "this fixture declares nothing, which is the point"
    );
}

#[test]
fn typosquats_and_custom_index_are_caught() {
    let out = scan_fixture("suspicious", "typosquat-deps");
    assert_trips(&out, &["DEP_TYPOSQUAT", "DEP_CUSTOM_REGISTRY"]);
    let typos: Vec<&str> = out
        .findings
        .iter()
        .filter(|f| f.rule.as_str() == "DEP_TYPOSQUAT")
        .map(|f| f.file.trim_start_matches("dependency:"))
        .collect();
    assert!(
        typos.contains(&"reqeusts"),
        "a transposition typosquat must be caught: {typos:?}"
    );
    assert!(
        typos.contains(&"numpyy"),
        "an inserted-character typosquat must be caught: {typos:?}"
    );
    assert!(
        typos.contains(&"cryptograpy"),
        "a deleted-character typosquat must be caught: {typos:?}"
    );
    assert!(
        !typos.contains(&"requests"),
        "the real package must not be flagged: {typos:?}"
    );
    assert!(
        !typos.contains(&"numpy"),
        "the real package must not be flagged: {typos:?}"
    );
    assert!(
        !typos.contains(&"python-dateutil"),
        "a hyphenated real package must not be flagged: {typos:?}"
    );
}

// ---------------------------------------------------------------------------
// obfuscated: normalization must defeat it
// ---------------------------------------------------------------------------

#[test]
fn zero_width_characters_do_not_hide_a_command() {
    let out = scan_fixture("obfuscated", "zero-width");
    assert_trips(&out, &["OBFUSC_ZERO_WIDTH"]);
    // After folding, the command is recognizable even though the raw bytes
    // spell it as c + zero-width + url.
    assert!(
        out.capabilities
            .network_outbound
            .iter()
            .any(|h| h.contains("plain.example.com")),
        "{:#?}",
        out.capabilities.network_outbound
    );
}

#[test]
fn homoglyphs_do_not_hide_a_command() {
    let out = scan_fixture("obfuscated", "homoglyph");
    assert_trips(&out, &["OBFUSC_HOMOGLYPH"]);
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule.as_str() == "DL_PIPE_TO_SHELL"),
        "once folded, curl ... | bash is recognizable: {:?}",
        rules(&out)
    );
    assert!(
        out.capabilities
            .network_outbound
            .iter()
            .any(|h| h.contains("plain.example.com")),
        "{:#?}",
        out.capabilities.network_outbound
    );
}

// ---------------------------------------------------------------------------
// edge cases: must not panic
// ---------------------------------------------------------------------------

#[test]
fn edge_case_fixtures_do_not_panic() {
    for sub in ["empty-skill", "weird-encoding", "huge-line"] {
        let out = scan_fixture("edge_cases", sub);
        // The only requirement is that we return, with the files we skipped
        // accounted for rather than silently dropped.
        assert!(
            !out.skill_name.is_empty(),
            "{sub} must still produce a named result"
        );
    }
}

#[test]
fn skipped_files_are_reported_not_hidden() {
    // Phase 0 depends on this: a batch scan that silently drops unreadable
    // files produces a corpus study with an invisible denominator.
    let out = scan_fixture("edge_cases", "weird-encoding");
    let skipped: Vec<&str> = out.skipped.iter().map(|s| s.file.as_str()).collect();
    assert!(
        skipped.iter().any(|f| f.ends_with("blob.js")),
        "a non-UTF-8 file must appear in the skipped list: {skipped:?}"
    );
    assert!(out.skipped.iter().all(|s| !s.reason.is_empty()));
}

// ---------------------------------------------------------------------------
// catalogue invariants
// ---------------------------------------------------------------------------

#[test]
fn every_rule_id_in_the_catalogue_is_documented() {
    for e in skillguard::scan::rules::catalogue() {
        assert!(e.id.starts_with(|c: char| c.is_ascii_uppercase()));
        assert!(!e.message.is_empty(), "{} needs a message", e.id);
        assert!(!e.remediation.is_empty(), "{} needs a fix", e.id);
    }
}

#[test]
fn scanning_is_reproducible_across_runs() {
    for (sub, name) in [
        ("malicious", "credential-stealer"),
        ("malicious", "download-execute"),
        ("safe", "table-formatter"),
    ] {
        let a = scan_fixture(sub, name);
        let b = scan_fixture(sub, name);
        let key = |o: &skillguard::scan::ScanOutcome| -> Vec<String> {
            o.findings
                .iter()
                .map(|f| {
                    format!(
                        "{}|{}|{}|{:?}",
                        f.rule,
                        f.file,
                        f.primary_line(),
                        f.severity
                    )
                })
                .collect()
        };
        assert_eq!(key(&a), key(&b), "{sub}/{name} is not deterministic");
    }
}
