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

#[test]
fn a_version_string_is_not_an_ip_endpoint() {
    // `research/GOLD.md` records `DL_UNTRUSTED_DOMAIN` reporting `Chrome/120.0.0.0`
    // (a user-agent version) as a raw IP endpoint. A dotted number is not a
    // destination, so the rule now requires network context.
    let out = scan_fixture("safe", "version-strings");
    assert!(
        !rules(&out).contains("DL_UNTRUSTED_DOMAIN"),
        "a version string is not an endpoint: {:#?}",
        out.findings
    );
    let noisy: Vec<String> = out
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .map(|f| f.rule.as_str().to_owned())
        .collect();
    assert!(
        noisy.is_empty(),
        "version-strings should be quiet: {noisy:?}"
    );
    assert!(
        out.capabilities.filesystem_read.is_empty(),
        "a user-agent version is not a path: {:#?}",
        out.capabilities
    );
}

#[test]
fn a_chmod_of_a_local_tmp_file_is_not_a_remote_install() {
    // A build script chmods a file it wrote to `/tmp` itself. The old
    // `DL_REMOTE_INSTALL` pattern accepted any `/tmp/` on a `chmod +x` line and
    // reported "installed directly from a URL" for a pure local build. The
    // script name must not become an observed outbound host either.
    let out = scan_fixture("safe", "tmp-chmod");
    assert!(
        !rules(&out).contains("DL_REMOTE_INSTALL"),
        "a local chmod is not a remote install: {:#?}",
        out.findings
    );
    assert!(
        out.capabilities.network_outbound.is_empty(),
        "a filename is not a host: {:#?}",
        out.capabilities.network_outbound
    );
    assert!(
        !out.capabilities
            .filesystem_read
            .iter()
            .any(|p| p == "/bin/sh"),
        "a shebang is not a read: {:#?}",
        out.capabilities.filesystem_read
    );
    let noisy: Vec<String> = out
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .map(|f| f.rule.as_str().to_owned())
        .collect();
    assert!(noisy.is_empty(), "tmp-chmod should be quiet: {noisy:?}");
}

#[test]
fn a_project_settings_file_is_not_agent_config() {
    // `PERSIST_AGENT_CONFIG` claims "the skill writes agent configuration". A
    // skill's own project-local `settings.json` is not agent configuration, and
    // GOLD-v5 measured the rule at 25% precision.
    let out = scan_fixture("safe", "own-settings");
    assert!(
        !rules(&out).contains("PERSIST_AGENT_CONFIG"),
        "a local settings file is not agent config: {:#?}",
        out.findings
    );
    let noisy: Vec<String> = out
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .map(|f| f.rule.as_str().to_owned())
        .collect();
    assert!(noisy.is_empty(), "own-settings should be quiet: {noisy:?}");
}

#[test]
fn a_credential_name_is_not_a_credential() {
    // `SECRET_GENERIC_ASSIGN` claims "a credential-shaped value is assigned to a
    // literal". Naming the environment variable, the field or a placeholder is
    // not assigning a credential; GOLD-v5 measured the rule at 12.5% precision.
    let out = scan_fixture("safe", "credential-names");
    assert!(
        !rules(&out).contains("SECRET_GENERIC_ASSIGN"),
        "a name is not a value: {:#?}",
        out.findings
    );
    let noisy: Vec<String> = out
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .map(|f| f.rule.as_str().to_owned())
        .collect();
    assert!(
        noisy.is_empty(),
        "credential-names should be quiet: {noisy:?}"
    );
}

#[test]
fn an_endpoint_is_judged_by_its_host_not_its_path() {
    // `DL_UNTRUSTED_DOMAIN` matched a `.xyz`/`.top`/`.rest` path segment as a
    // low-reputation TLD, and its private-address exclusion never fired because
    // it compared the whole match (`http://127.0.0.1`) against `127.`. Both are
    // rev 27.
    let out = scan_fixture("safe", "endpoint-context");
    assert!(
        !rules(&out).contains("DL_UNTRUSTED_DOMAIN"),
        "a path segment or a local address is not an untrusted endpoint: {:#?}",
        out.findings
    );
    let noisy: Vec<String> = out
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .map(|f| f.rule.as_str().to_owned())
        .collect();
    assert!(
        noisy.is_empty(),
        "endpoint-context should be quiet: {noisy:?}"
    );
}

#[test]
fn a_comment_is_not_a_capability() {
    // `research/GOLD.md` records a documentation path mentioned in a `//`
    // comment being counted as `fs read`. A comment describes behaviour; it does
    // not perform it, so it must not grant a capability that then drives a
    // declared-vs-observed mismatch.
    let out = scan_fixture("safe", "comment-mentions");
    assert!(
        out.capabilities.filesystem_read.is_empty(),
        "a commented path is not a read: {:#?}",
        out.capabilities
    );
    assert!(
        out.capabilities.network_outbound.is_empty(),
        "a commented host is not an outbound call: {:#?}",
        out.capabilities
    );
    assert!(!out.capabilities.secrets_read);
    assert!(
        out.findings.is_empty(),
        "a comment mention is not a finding: {:#?}",
        out.findings
    );
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
fn a_raw_ip_endpoint_is_caught() {
    // Tightening the IPv4 pattern must not blind the rule to a real destination.
    let out = scan_fixture("suspicious", "raw-ip-endpoint");
    assert_trips(&out, &["DL_UNTRUSTED_DOMAIN"]);
}

#[test]
fn a_url_path_segment_is_not_a_host() {
    // `http://198.51.100.7/install.sh` names `install.sh` in the path. `.sh` is a
    // TLD too, but the URL authority ended at the first `/`.
    let out = scan_fixture("suspicious", "raw-ip-endpoint");
    assert!(
        !rules(&out).contains("NET_DOMAIN_LITERAL"),
        "a path segment is not a host: {:#?}",
        out.findings
    );
}

#[test]
fn an_ambiguous_tld_in_host_position_is_still_a_host() {
    // The path fix must not blind the rule to a real host whose TLD looks like a
    // file extension.
    let out = scan_fixture("suspicious", "ambiguous-tld-host");
    assert_trips(&out, &["NET_DOMAIN_LITERAL"]);
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

#[test]
fn read_write_classification_comes_from_the_call() {
    // Issue #3: the read/write split decides whether a `filesystem.write` policy
    // violation fires, so it must come from the call, not from nearby text.
    let out = scan_fixture("suspicious", "io-classification");
    let w = &out.capabilities.filesystem_write;
    let r = &out.capabilities.filesystem_read;
    for name in ["out.csv", "out.txt", "log.txt", "report.md"] {
        assert!(w.iter().any(|p| p.ends_with(name)), "{name} write: {w:?}");
    }
    for name in ["input.txt", "in.txt", "data/x.csv"] {
        assert!(r.iter().any(|p| p.ends_with(name)), "{name} read: {r:?}");
    }
    // The unresolved mode must be surfaced, not silently claimed as a read.
    let note = out
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "FS_MODE_UNRESOLVED")
        .expect("a variable mode must produce a finding");
    assert!(note.message.contains("x.csv"), "{}", note.message);
    assert!(
        note.evidence.iter().all(|e| !e.text.is_empty()),
        "invariant S3: no evidence, no finding"
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
    for sub in [
        "empty-skill",
        "weird-encoding",
        "huge-line",
        "unicode-torture",
    ] {
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
// declared vs observed: the differentiator
// ---------------------------------------------------------------------------

#[test]
fn undeclared_egress_is_detected() {
    let out = scan_fixture("suspicious", "undeclared-egress");
    assert!(
        out.declared.declared,
        "this fixture must declare something, or there is nothing to diff"
    );
    let under: Vec<&str> = out
        .diff
        .blocking()
        .iter()
        .map(|m| m.detail.as_str())
        .collect();
    assert!(
        under
            .iter()
            .any(|d| d.contains("telemetry.weather-analytics.example.net")),
        "egress to an undeclared host is the finding this project exists for: {under:?}"
    );
    assert!(
        !under.iter().any(|d| d.contains("weather.example.com")),
        "the declared host must not be reported: {under:?}"
    );
}

#[test]
fn mismatches_surface_as_ordinary_findings() {
    // They have to flow through SARIF and `--fail-on`, so they must be findings.
    let out = scan_fixture("suspicious", "undeclared-egress");
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule.as_str() == "MISMATCH_UNDER_DECLARED"),
        "{:?}",
        out.findings
            .iter()
            .map(|f| f.rule.0.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn secrets_false_conflicts_with_observed_secret_access() {
    let out = scan_fixture("suspicious", "undeclared-egress");
    // This fixture declares `secrets.access: false` and does not read secrets,
    // so there must be no conflict. A positive control for the rule's silence.
    assert!(
        !out.diff
            .mismatches
            .iter()
            .any(|m| m.kind == skillguard::MismatchKind::Conflicting),
        "{:#?}",
        out.diff
    );
}

#[test]
fn adopting_then_diffing_is_clean() {
    // The bootstrap loop must actually close: adopt derives a declaration from
    // observation, and diffing against it must then find nothing.
    let dir = fixtures("suspicious").join("undeclared-egress");
    let before = scan_skill(&dir);
    assert!(
        !before.diff.blocking().is_empty(),
        "fixture must start with undeclared behaviour"
    );
    let derived = before.declared_from_observed();
    let after = skillguard::permissions::diff(&derived, &before.capabilities);
    assert!(
        after.blocking().is_empty(),
        "a declaration derived from observation must diff clean: {:#?}",
        after.mismatches
    );
}

#[test]
fn adopt_is_idempotent_and_preserves_the_rest_of_the_file() {
    let src = std::fs::read_to_string(fixtures("suspicious").join("undeclared-egress/SKILL.md"))
        .expect("fixture");
    // Derive a block and write it twice; the second write must be a no-op.
    let out = scan_skill(&fixtures("suspicious").join("undeclared-egress"));
    let block = skillguard::permissions::to_yaml(&out.declared_from_observed());
    let once = replace_block(&src, &block);
    let twice = replace_block(&once, &block);
    assert_eq!(once, twice, "adopt must be idempotent");
    assert!(once.contains("name: weather-report"), "name must survive");
    assert!(
        once.contains("Calls the weather API"),
        "the body must survive"
    );
    assert!(
        once.contains("telemetry.weather-analytics.example.net"),
        "the derived block must describe the observed host"
    );
}

/// Mirror of the binary's frontmatter rewrite, for testing without touching disk.
fn replace_block(src: &str, block: &str) -> String {
    let split = skillguard::parser::split_frontmatter(src);
    let (yaml, _) = split.frontmatter.expect("fixture has frontmatter");
    let mut kept: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in yaml.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim_end();
        if indent == 0 {
            let key = t.split(':').next().unwrap_or("").trim();
            skipping = matches!(key, "permissions" | "skillguard.permissions");
            if skipping {
                continue;
            }
        }
        if !skipping {
            kept.push(t);
        }
    }
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    let mut new_yaml: String = kept.iter().map(|l| format!("{l}\n")).collect();
    new_yaml.push('\n');
    new_yaml.push_str(block);
    let body = split.body.trim_start_matches('\n');
    format!("---\n{new_yaml}---\n\n{body}")
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
