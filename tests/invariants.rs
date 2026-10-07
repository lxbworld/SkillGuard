//! Architectural invariants, enforced against the source tree.
//!
//! `docs/ARCHITECTURE.md` §2 states negative-space rules that are easy to
//! violate by accident and impossible to express in the type system: the
//! scanner must never reach the network, must never spawn a process, and the
//! binary must contain no `unsafe`. These checks are blunt, but they are the
//! only ones that run on every push and fail a pull request that adds
//! `std::net` to the scanner (issue #6).
//!
//! They are deliberately source-level: a dependency could bring networking in,
//! which is what `cargo deny` and the dependency review are for. Together they
//! cover "no socket of our own" and "no socket from a crate we pulled in".

use std::path::{Path, PathBuf};
use std::process::Command;

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources() -> Vec<PathBuf> {
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                visit(&p, out);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    visit(&src_root(), &mut out);
    out.sort();
    out
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn the_binary_never_opens_a_socket() {
    // Invariant S1: the scanner reads bytes and nothing else.
    let mut checked = 0usize;
    for f in rust_sources() {
        let body = read(&f);
        if body.contains("std::net") || body.contains("TcpStream") || body.contains("UdpSocket") {
            panic!(
                "{} reaches the network; the scanner must not (invariant S1)",
                f.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 10, "expected to check the whole source tree");
}

#[test]
fn only_provenance_spawns_a_process() {
    // Invariant S1 allows exactly one narrow exception: reading local git
    // metadata in hash.rs. Everything else must not exec anything, because the
    // scanned skill is hostile input.
    let mut spawners: Vec<String> = Vec::new();
    for f in rust_sources() {
        let body = read(&f);
        if body.contains("std::process::Command") {
            spawners.push(
                f.strip_prefix(src_root())
                    .unwrap_or(&f)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    assert_eq!(
        spawners,
        vec!["hash.rs".to_owned()],
        "only provenance (hash.rs) may spawn a subprocess"
    );
}

#[test]
fn the_whole_binary_forbids_unsafe() {
    // The library forbids it; the binary must too, or the CLI becomes a way in.
    for entry in ["lib.rs", "main.rs"] {
        let body = read(&src_root().join(entry));
        assert!(
            body.contains("#![forbid(unsafe_code)]"),
            "src/{entry} must forbid unsafe code"
        );
    }
}

#[test]
fn the_rule_reference_matches_the_code() {
    // docs/RULES.md is generated from `skillguard rules --format markdown`.
    // Regenerating it here and comparing means the committed reference cannot
    // drift from the rule set (issue #4).
    let out = Command::new(env!("CARGO_BIN_EXE_skillguard"))
        .args(["rules", "--format", "markdown"])
        .output()
        .expect("run skillguard rules");
    assert!(out.status.success(), "rules command failed");
    let generated = String::from_utf8_lossy(&out.stdout).into_owned();
    let committed =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/RULES.md"))
            .expect("docs/RULES.md must exist");
    assert!(
        committed.contains(generated.trim()),
        "docs/RULES.md has drifted from the rule catalogue; \
         regenerate it with `skillguard rules --format markdown`"
    );
    assert!(
        generated.lines().count() > 40,
        "the catalogue looks empty; the drift check would be vacuous"
    );
}

#[test]
fn no_telemetry_crate_is_a_dependency() {
    // The README makes offline operation a project constraint. A usage ping
    // would contradict the one thing the commercial alternatives cannot offer,
    // so it is mechanically excluded rather than left to review.
    let cargo = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("Cargo.toml");
    let lowered = cargo.to_lowercase();
    for needle in [
        "telemetry",
        "sentry",
        "opentelemetry",
        "posthog",
        "mixpanel",
        "segment",
        "analytics",
        "reqwest",
    ] {
        assert!(
            !lowered.contains(needle),
            "Cargo.toml mentions `{needle}`; the offline promise is a constraint, not a preference"
        );
    }
}
