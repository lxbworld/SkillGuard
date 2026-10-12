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
    // Compare modulo line endings: a Windows checkout can hand back CRLF even
    // though `.gitattributes` asks for LF, and a line ending is not drift.
    let committed = committed.replace("\r\n", "\n");
    let generated = generated.replace("\r\n", "\n");
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

/// The targets of `](...)` in a Markdown body, without pulling in a regex
/// dependency. A target stops at whitespace, so `](a b)` is not a link.
fn link_targets(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b']' && bytes[i + 1] == b'(' {
            let start = i + 2;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b')' && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b')' {
                if let Ok(s) = std::str::from_utf8(&bytes[start..j]) {
                    out.push(s.to_owned());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn relative_markdown_links_resolve() {
    // A pointer to a moved file is a small lie, and this repository has already
    // been bitten by documentation drifting from the code (the rule reference).
    // Absolute URLs, anchors and code samples are not checked.
    //
    // Only files this repository *authors* are checked. Walking the tree instead
    // reads `research/raw/`, the gitignored third-party corpus, whose SKILL.md
    // files contain relative links that were never ours to fix — which made
    // this test red on every machine that had collected the corpus and green in
    // CI, where that directory does not exist. A test that depends on which
    // machine runs it is worse than no test.
    fn walk(dir: &Path, out: &mut Vec<PathBuf>, skip_data: bool) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if p.is_dir() {
                let is_data = matches!(name, "raw" | "lists")
                    && p.parent().and_then(|q| q.file_name()) == Some("research".as_ref());
                if name != "target" && name != ".git" && !(skip_data && is_data) {
                    walk(&p, out, skip_data);
                }
            } else if p.extension().map(|x| x == "md").unwrap_or(false) {
                out.push(p);
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Preferred: ask git, so the answer is "the files we publish" and there is
    // no exclusion list to keep in sync as the repository grows.
    let mut files: Vec<PathBuf> = Vec::new();
    if let Ok(out) = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
    {
        if out.status.success() {
            files = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|line| root.join(line))
                .filter(|p| p.exists())
                .collect();
        }
    }
    // No git (a source tarball): walk, but skip the data directories by name.
    if files.is_empty() {
        walk(root, &mut files, true);
    }
    files.sort();

    let mut broken = Vec::new();
    for f in &files {
        for target in link_targets(&read(f)) {
            let t = target.split('#').next().unwrap_or("");
            if t.is_empty() || t.starts_with("http") || t.starts_with("mailto:") {
                continue;
            }
            // An inline code span can look like a link; skip it.
            if t.contains('`') || t.contains('|') {
                continue;
            }
            let resolved = f.parent().unwrap_or(root).join(t);
            if !resolved.exists() {
                broken.push(format!("{}: {t}", f.display()));
            }
        }
    }
    assert!(!files.is_empty(), "expected to check the docs");
    assert!(broken.is_empty(), "broken relative links: {broken:#?}");
}

/// The README states the rule count. A count that drifts is a small lie, and
/// `docs/RULES.md` already has a test against exactly that.
#[test]
fn the_readme_rule_count_matches_the_code() {
    let readme = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"));
    let expected = skillguard::scan::rules::rule_count();
    let mut checked = 0usize;
    for (idx, _) in readme.match_indices(" rules") {
        let digits: String = readme[..idx]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            continue;
        }
        let n: usize = digits
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .expect("digits parse");
        assert_eq!(
            n, expected,
            "README says `{n} rules` but the code emits {expected}"
        );
        checked += 1;
    }
    assert!(checked > 0, "the README should state the rule count");
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
