//! SkillGuard CLI.
//!
//! Exit codes are part of the contract (see `skillguard::exit`):
//! 0 clean · 1 findings at/above `--fail-on` · 2 integrity · 3 usage · 4 internal.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use skillguard::exit;
use skillguard::models::Severity;
use skillguard::report::{Format, Report, SkillReport};
use skillguard::scan::{self, scan_skill, ScanOutcome};
use skillguard::text;
use skillguard::walk;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "skillguard",
    version,
    about = "Offline, deterministic verification layer for AI Agent Skills",
    long_about = "SkillGuard scans Agent Skills and reports evidence-grade security findings.\n\n\
                  It never executes what it scans, never opens a network connection, and never \
                  calls a language model. Every finding carries a file, a line and the original \
                  text, because detection is not judgement.",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress ANSI colour. Also honours the NO_COLOR environment variable.
    #[arg(long, global = true)]
    no_color: bool,

    /// Write the report to this file instead of stdout.
    #[arg(long, short, global = true, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan one or more skills and report findings with evidence.
    Scan {
        /// Skill directory, or a directory containing skills. Repeatable.
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        #[arg(long, short, default_value = "text", value_enum)]
        format: Format,

        /// Exit non-zero when a finding at or above this severity exists.
        #[arg(long, default_value = "critical")]
        fail_on: String,

        /// Print the rule catalogue instead of scanning.
        #[arg(long)]
        list_rules: bool,
    },

    /// Report observed capabilities and dependencies. Makes no judgement.
    Inspect {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        #[arg(long, short, default_value = "text", value_enum)]
        format: Format,

        /// Print only normalized text with line numbers, for GOLD labelling.
        /// No capabilities and no findings, so an annotator is not anchored by
        /// the scanner's output (research/PROTOCOL.md §4.3).
        #[arg(long)]
        labeling: bool,
    },

    /// Compare the skill's declared permissions against observed behaviour.
    ///
    /// This is the check no other tool performs: it answers "does the skill do
    /// anything it did not say it would do?"
    Diff {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Treat undeclared behaviour as a failure, not a warning.
        #[arg(long)]
        strict: bool,
    },

    /// Write a permissions block derived from observed behaviour into SKILL.md.
    ///
    /// Bootstrap tool: the ecosystem has no manifest convention yet, so this
    /// creates one from what a skill actually does. Review it, commit it, and
    /// every later `skillguard diff` has something to verify against.
    Adopt {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Print the block instead of writing it.
        #[arg(long)]
        dry_run: bool,
    },

    /// Evaluate a policy against what a skill actually does.
    PolicyCheck {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Policy file. Defaults to SKILLGUARD.policy.yaml next to the lockfile,
        /// then to a permissive built-in policy.
        #[arg(long, short = 'c')]
        policy: Option<PathBuf>,
    },

    /// Recompute source, commit and content digest, and compare to the lockfile.
    ///
    /// Nothing recorded in the lockfile is trusted: every value is re-derived
    /// from the bytes on disk.
    Verify {
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,

        /// Lockfile to verify against. Defaults to SKILLGUARD.lock in each
        /// skill directory.
        #[arg(long, short)]
        lockfile: Option<PathBuf>,
    },

    /// Write or update SKILLGUARD.lock from the current state on disk.
    Lock {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Lockfile path. Defaults to SKILLGUARD.lock beside each skill.
        ///
        /// Long form only: the short `-o` belongs to the global `--output`.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Record an approval for a skill, bound to its current content digest.
    Approve {
        #[arg(value_name = "PATH", required = true)]
        path: PathBuf,

        /// Who is approving. Recorded in the audit trail.
        #[arg(long)]
        reviewer: String,

        /// Why. Recorded in the audit trail and required.
        #[arg(long)]
        reason: String,

        /// Record the approval even though the policy denies the skill.
        ///
        /// Required to override a `deny`: a denial is never rewritten into an
        /// `allow`, the lockfile keeps `policy_decision: deny` and records the
        /// violations the approval accepted.
        #[arg(long)]
        force: bool,

        #[arg(long, short)]
        lockfile: Option<PathBuf>,
    },

    /// Import a foreign lockfile (skills-lock.json) into SKILLGUARD.lock.
    ///
    /// Interoperability, not replacement: the imported digest is retained as
    /// `legacy_digest` so the original tool's own verification still works.
    Import {
        /// The file to read, e.g. skills-lock.json.
        #[arg(value_name = "FILE", required = true)]
        file: PathBuf,

        /// Long form only: the short `-o` belongs to the global `--output`.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Print the rule catalogue.
    Rules {
        #[arg(long, short, default_value = "text", value_enum)]
        format: Format,
    },

    /// Phase 0 corpus study: index, batch-scan and measure, offline.
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },
}

#[derive(Subcommand)]
enum CorpusCommand {
    /// Index a local tree of skills into a manifest (deterministic, offline).
    Index {
        /// Directory containing skills (searched recursively).
        source: PathBuf,

        /// Directory the manifest paths are relative to. Defaults to `source`.
        #[arg(long)]
        tree: Option<PathBuf>,

        /// Sampling layer: L1..L5.
        #[arg(long, default_value = "L3")]
        layer: String,

        /// Prefix for source ids that have no git repository, e.g. `local`.
        #[arg(long, default_value = "local")]
        source_prefix: String,

        #[arg(long)]
        out: PathBuf,
    },

    /// Ingest an already-downloaded tree into a manifest.
    ///
    /// Network fetching is deliberately absent until collection is cleared
    /// (issue #5): only GitHub code search is permitted, and the registries
    /// have not replied. This performs the deterministic half of `fetch`
    /// deriving digests, commits and strata from a tree you obtained yourself,
    /// which is the same work for every source.
    Fetch {
        /// Tree of skills that have already been downloaded.
        #[arg(long)]
        from_dir: PathBuf,

        /// Directory the manifest paths are relative to. Defaults to `--from-dir`.
        #[arg(long)]
        tree: Option<PathBuf>,

        #[arg(long, default_value = "L3")]
        layer: String,

        #[arg(long, default_value = "local")]
        source_prefix: String,

        #[arg(long)]
        out: PathBuf,
    },

    /// Scan every manifest entry. Offline, cached by content digest.
    Scan {
        #[arg(long)]
        manifest: PathBuf,

        /// Root the manifest paths are relative to.
        #[arg(long)]
        tree: PathBuf,

        #[arg(long)]
        out: PathBuf,

        /// Cache file. Defaults to `<out>.cache.json`.
        #[arg(long)]
        cache: Option<PathBuf>,
    },

    /// Stratified prevalence from a findings JSONL.
    Stats {
        #[arg(long)]
        findings: PathBuf,

        /// Dimensions to stratify on; `layer` is its own field, the rest are
        /// keys in each entry's `stratum` map.
        #[arg(long, default_value = "layer,size,scripts,declared,license")]
        by: String,

        #[arg(long, short, default_value = "markdown", value_enum)]
        format: Format,
    },

    /// Write the Markdown report for a findings JSONL.
    Report {
        #[arg(long)]
        findings: PathBuf,

        /// Optional GOLD label set (JSONL) for per-rule precision and recall.
        #[arg(long)]
        gold: Option<PathBuf>,

        #[arg(long)]
        out: PathBuf,
    },

    /// Recompute every manifest digest and compare. The reproducibility check.
    Reproduce {
        #[arg(long)]
        manifest: PathBuf,

        #[arg(long)]
        tree: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap already formatted the message; help goes to stdout, errors to stderr.
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(exit::USAGE as u8)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none();

    let result = match &cli.command {
        Command::Scan {
            paths,
            format,
            fail_on,
            list_rules,
        } => run_scan(paths, *format, fail_on, *list_rules, &cli, color),
        Command::Inspect {
            paths,
            format,
            labeling,
        } => {
            if *labeling {
                run_labeling(paths, &cli)
            } else {
                run_inspect(paths, *format, &cli, color)
            }
        }
        Command::Diff { paths, strict } => run_diff(paths, *strict, &cli),
        Command::Adopt { paths, dry_run } => run_adopt(paths, *dry_run, &cli),
        Command::PolicyCheck { paths, policy } => run_policy_check(paths, policy.as_deref(), &cli),
        Command::Verify { paths, lockfile } => run_verify(paths, lockfile.as_deref(), &cli),
        Command::Lock { paths, out } => run_lock(paths, out.as_deref(), &cli),
        Command::Approve {
            path,
            reviewer,
            reason,
            force,
            lockfile,
        } => run_approve(path, reviewer, reason, *force, lockfile.as_deref(), &cli),
        Command::Import { file, out } => run_import(file, out.as_deref(), &cli),
        Command::Rules { format } => run_rules(*format, &cli, color),
        Command::Corpus { command } => run_corpus(command, &cli),
    };

    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("skillguard: {e}");
            ExitCode::from(exit::USAGE as u8)
        }
    }
}

/// RFC 3339 to second precision. Nanosecond timestamps make every `lock` run a
/// diff, which trains people to ignore the lockfile.
fn now_rfc3339() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Days since epoch -> civil date (Howard Hinnant's algorithm).
            let days = (secs / 86_400) as i64;
            let rem = secs % 86_400;
            let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
            let (y, mo, dd) = civil_from_days(days);
            format!("{y:04}-{mo:02}-{dd:02}T{h:02}:{mi:02}:{s:02}Z")
        }
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Locate a skill directory from a path that may be the skill or its SKILL.md.
fn skill_dir_of(path: &std::path::Path) -> Result<PathBuf, String> {
    if path.is_file() {
        return path.parent().map(Path::to_path_buf).ok_or_else(|| {
            format!(
                "cannot determine the skill directory for {}",
                path.display()
            )
        });
    }
    if path.join("SKILL.md").is_file() {
        return Ok(path.to_path_buf());
    }
    Err(format!("no SKILL.md in {}", path.display()))
}

fn default_lockfile(dir: &std::path::Path) -> PathBuf {
    skillguard::policy::Lockfile::path(dir)
}

/// The policy that applies to a skill: `SKILLGUARD.policy.yaml` beside it, or a
/// permissive default. A malformed policy is an error, never silently ignored.
fn policy_for_dir(dir: &std::path::Path) -> Result<skillguard::policy::Policy, String> {
    let path = dir.join("SKILLGUARD.policy.yaml");
    if path.is_file() {
        skillguard::policy::load_policy(&path)
    } else {
        Ok(skillguard::policy::Policy::new())
    }
}

fn run_policy_check(
    paths: &[PathBuf],
    policy_path: Option<&std::path::Path>,
    cli: &Cli,
) -> Result<i32, String> {
    let targets = resolve_targets(paths)?;
    let mut all_blocked = false;
    let mut o = String::from("\n  SkillGuard policy\n");

    for t in &targets {
        let dir = skill_dir_of(t)?;
        let policy_file = policy_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.join("SKILLGUARD.policy.yaml"));
        let policy = if policy_file.is_file() {
            skillguard::policy::load_policy(&policy_file)?
        } else {
            skillguard::policy::Policy::new()
        };

        let out = scan_skill(&dir);
        let findings = policy.apply_ignores(out.findings.clone());
        let subject = skillguard::policy::Subject {
            name: &out.skill_name,
            capabilities: &out.capabilities,
            diff: &out.diff,
            findings: &findings,
            source: None,
            approved_digest: None,
        };
        let decision = skillguard::policy::evaluate(&policy, &subject);

        o.push_str(&format!("\n  {}\n", out.skill_name));
        o.push_str(&skillguard::policy::render_decision(&decision));
        o.push_str(&format!(
            "    policy: {}\n",
            if policy_file.is_file() {
                policy_file.display().to_string()
            } else {
                "built-in default (no SKILLGUARD.policy.yaml found)".to_owned()
            }
        ));
        if decision.decision.blocks() {
            all_blocked = true;
        }
    }

    o.push('\n');
    emit(cli, &o)?;
    Ok(if all_blocked {
        exit::FINDINGS
    } else {
        exit::OK
    })
}

fn run_verify(
    paths: &[PathBuf],
    lockfile: Option<&std::path::Path>,
    cli: &Cli,
) -> Result<i32, String> {
    let targets = if paths.is_empty() {
        vec![std::path::PathBuf::from(".")]
    } else {
        resolve_targets(paths)?
    };

    let mut o = String::from("\n  SkillGuard verify - source + commit + content digest\n");
    let mut all_ok = true;

    for t in &targets {
        let dir = skill_dir_of(t)?;
        let lock_path = lockfile
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_lockfile(&dir));
        let lock = skillguard::policy::Lockfile::load(&lock_path)?;
        let name = dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "skill".to_owned());

        let Some(entry) = lock.skills.get(&name) else {
            o.push_str(&format!(
                "\n  {name}\n    [FAIL] not_locked     {} has no entry\n",
                lock_path.display()
            ));
            all_ok = false;
            continue;
        };

        let collected = skillguard::hash::collect(&dir, entry.license.as_deref())?;
        match skillguard::policy::VerifyReport::run(&name, &dir, entry, &collected.provenance) {
            Ok(report) => {
                o.push_str(&report.render());
                all_ok &= report.ok;
            }
            Err(e) => {
                o.push_str(&format!("\n  {name}\n    [FAIL] {e}\n"));
                all_ok = false;
            }
        }
    }

    o.push_str(if all_ok {
        "  integrity verified\n\n"
    } else {
        "  INTEGRITY FAILURE\n\n"
    });
    emit(cli, &o)?;
    Ok(if all_ok { exit::OK } else { exit::INTEGRITY })
}

fn run_lock(paths: &[PathBuf], out: Option<&std::path::Path>, cli: &Cli) -> Result<i32, String> {
    let targets = resolve_targets(paths)?;
    let mut o = String::from("\n  SkillGuard lock\n");

    for t in &targets {
        let dir = skill_dir_of(t)?;
        let name = dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "skill".to_owned());
        let lock_path = out
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_lockfile(&dir));

        let scan = scan_skill(&dir);
        let collected = skillguard::hash::collect(&dir, scan.license_declared.as_deref())?;
        let policy = policy_for_dir(&dir)?;
        let findings = policy.apply_ignores(scan.findings.clone());
        let decision = skillguard::policy::evaluate(
            &policy,
            &skillguard::policy::Subject {
                name: &name,
                capabilities: &scan.capabilities,
                diff: &scan.diff,
                findings: &findings,
                source: None,
                approved_digest: None,
            },
        );

        let mut lock = skillguard::policy::Lockfile::load(&lock_path)
            .unwrap_or_else(|_| skillguard::policy::Lockfile::new());
        // Preserve an existing approval only while the content it covers is
        // unchanged; otherwise the entry is rebuilt without it.
        let prior_approval = lock
            .skills
            .get(&name)
            .and_then(|e| e.approved_by.clone())
            .filter(|a| a.content_digest == collected.digest.as_str());

        let existed = lock.skills.contains_key(&name);
        lock.rule_set_version = skillguard::RULE_SET_VERSION.to_owned();
        lock.generated_by = format!("{} {}", skillguard::policy::TOOL, env!("CARGO_PKG_VERSION"));
        lock.verifier = lock.generated_by.clone();
        lock.skills.insert(
            name.clone(),
            skillguard::policy::LockSkill {
                source: collected.provenance.source.clone(),
                repository: collected.provenance.repository.clone(),
                commit: collected.provenance.commit.clone(),
                content_digest: collected.digest.as_str().to_owned(),
                files: collected.files.clone(),
                legacy_digest: None,
                version: None,
                license: scan.license_declared.clone(),
                declared_permissions: scan.declared.clone(),
                observed_capabilities: scan.capabilities.clone(),
                mismatches: scan.diff.mismatches.clone(),
                dependencies: scan.dependencies.clone(),
                policy_decision: decision.decision,
                approved_by: prior_approval,
                observed_at: now_rfc3339(),
            },
        );

        lock.save(&lock_path)?;
        o.push_str(&format!(
            "    {}  {}  {}  -> {}\n",
            name,
            if existed { "updated" } else { "created" },
            collected.digest,
            lock_path.display()
        ));
        if collected.provenance.incomplete {
            o.push_str(&format!(
                "      note: {}\n",
                collected
                    .provenance
                    .note
                    .as_deref()
                    .unwrap_or("provenance incomplete")
            ));
        }
        if decision.decision.blocks() {
            o.push_str("      BLOCKED by policy: this lock records state, not approval\n");
        }
    }

    o.push_str("\n  Commit the lockfile. It is the audit trail.\n\n");
    emit(cli, &o)?;
    Ok(exit::OK)
}

fn run_approve(
    path: &std::path::Path,
    reviewer: &str,
    reason: &str,
    force: bool,
    lockfile: Option<&std::path::Path>,
    cli: &Cli,
) -> Result<i32, String> {
    if reason.trim().is_empty() {
        return Err(
            "--reason is required: an approval without a reason is not an audit trail".to_owned(),
        );
    }
    let dir = skill_dir_of(path)?;
    let name = dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "skill".to_owned());
    let lock_path = lockfile
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_lockfile(&dir));

    // A missing lockfile is fine (this is the first approval); an existing but
    // malformed one is not, because silently replacing it would discard the
    // audit trail.
    let mut lock = if lock_path.exists() {
        skillguard::policy::Lockfile::load(&lock_path)?
    } else {
        skillguard::policy::Lockfile::new()
    };
    let digest = skillguard::hash::digest_dir(&dir)?.0;

    // Approve what is on disk *now*, not what the lockfile claims: the whole
    // point of an approval is that a human looked at these bytes.
    let scan = scan_skill(&dir);
    let collected = skillguard::hash::collect(&dir, scan.license_declared.as_deref())?;

    // Evaluate the policy *before* anything is written. Recording `allow` for a
    // skill the engine denies is not an audit trail; it is a record of the
    // outcome with the reason stripped out (issue #7).
    let policy = policy_for_dir(&dir)?;
    let findings = policy.apply_ignores(scan.findings.clone());
    let decision = skillguard::policy::evaluate(
        &policy,
        &skillguard::policy::Subject {
            name: &name,
            capabilities: &scan.capabilities,
            diff: &scan.diff,
            findings: &findings,
            source: collected.provenance.source.as_deref(),
            approved_digest: None,
        },
    );

    // A human with context is the final authority, including over a CRITICAL
    // denial -- but the override must be deliberate. A `deny` therefore needs
    // `--force`, and either way the denial stays on the record. See
    // docs/THREAT_MODEL.md T17 for the decision this settles.
    if decision.decision.blocks() && !force {
        let mut msg = format!("the policy denies {name}; refusing to record an approval");
        for v in decision.violations.iter().take(5) {
            msg.push_str(&format!(
                "\n    {}  {:<18} {}",
                v.severity,
                v.capability,
                text::sanitize_for_display(&v.detail)
            ));
        }
        if decision.violations.is_empty() {
            if let Some(w) = decision.worst_finding {
                msg.push_str(&format!(
                    "\n    {w}  finding at or above the deny threshold"
                ));
            }
        }
        msg.push_str(
            "\n  Pass --force to record an approval that overrides the denial, or fix the skill.",
        );
        return Err(msg);
    }

    let entry = lock
        .skills
        .entry(name.clone())
        .or_insert_with(|| skillguard::policy::LockSkill {
            source: None,
            repository: None,
            commit: None,
            content_digest: digest.as_str().to_owned(),
            files: collected.files.clone(),
            legacy_digest: None,
            version: None,
            license: None,
            declared_permissions: Default::default(),
            observed_capabilities: Default::default(),
            mismatches: vec![],
            dependencies: vec![],
            policy_decision: skillguard::policy::Decision::Allow,
            approved_by: None,
            observed_at: now_rfc3339(),
        });

    entry.content_digest = digest.as_str().to_owned();
    entry.files = collected.files.clone();
    entry.source = collected.provenance.source.clone();
    entry.repository = collected.provenance.repository.clone();
    entry.commit = collected.provenance.commit.clone();
    entry.license = scan.license_declared.clone();
    entry.declared_permissions = scan.declared.clone();
    entry.observed_capabilities = scan.capabilities.clone();
    entry.mismatches = scan.diff.mismatches.clone();
    entry.observed_at = now_rfc3339();
    // Never rewrite deny into allow: an approval is recorded *beside* the
    // decision, not instead of it (issue #7, invariant I2).
    entry.policy_decision = decision.decision;
    entry.approved_by = Some(skillguard::policy::Approval {
        reviewer: reviewer.to_owned(),
        reason: reason.to_owned(),
        approved_at: now_rfc3339(),
        content_digest: digest.as_str().to_owned(),
        note: None,
        overrode_decision: (decision.decision != skillguard::policy::Decision::Allow)
            .then_some(decision.decision),
        overrode_violations: decision.violations.clone(),
    });

    lock.save(&lock_path)?;

    let mut o = String::new();
    o.push_str(&format!("\n  approved  {name}\n"));
    o.push_str(&format!("    digest:    {digest}\n"));
    o.push_str(&format!(
        "    decision:  {} (recorded, not rewritten)\n",
        decision.decision.as_str()
    ));
    if !decision.violations.is_empty() {
        o.push_str("    accepted (the approval overrides these):\n");
        for v in &decision.violations {
            o.push_str(&format!(
                "      {}  {:<18} {}\n",
                v.severity,
                v.capability,
                text::sanitize_for_display(&v.detail)
            ));
        }
    }
    o.push_str(&format!("    file:      {}\n", lock_path.display()));
    o.push_str("\n  This approval is bound to that digest. If the content changes,\n");
    o.push_str("  the approval stops applying and must be granted again.\n\n");
    emit(cli, &o)?;
    Ok(exit::OK)
}

fn run_import(
    file: &std::path::Path,
    out: Option<&std::path::Path>,
    cli: &Cli,
) -> Result<i32, String> {
    let entries = skillguard::import::read_foreign_lock(file)?;
    let dest = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("SKILLGUARD.lock"));
    let mut lock = skillguard::policy::Lockfile::load(&dest)
        .unwrap_or_else(|_| skillguard::policy::Lockfile::new());
    lock.rule_set_version = skillguard::RULE_SET_VERSION.to_owned();

    let mut o = String::from("\n  SkillGuard import\n");
    for e in entries {
        let digest = e
            .digest
            .clone()
            .unwrap_or_else(|| "<no digest recorded>".to_owned());
        o.push_str(&format!("    {:<32} {digest}\n", e.name));
        lock.skills.insert(
            e.name.clone(),
            skillguard::policy::LockSkill {
                source: Some(e.source.clone()),
                repository: None,
                commit: e.commit.clone(),
                content_digest: digest.clone(),
                // Not recorded: a foreign lockfile has no per-file inventory.
                files: vec![],
                // Retained so the original tool's verification still works.
                legacy_digest: e.digest.clone(),
                version: e.version.clone(),
                license: None,
                declared_permissions: Default::default(),
                observed_capabilities: Default::default(),
                mismatches: vec![],
                dependencies: vec![],
                policy_decision: skillguard::policy::Decision::Warn,
                approved_by: None,
                observed_at: now_rfc3339(),
            },
        );
    }
    lock.save(&dest)?;
    o.push_str(&format!(
        "\n  {} entr(ies) -> {}\n",
        lock.skills.len(),
        dest.display()
    ));
    o.push_str("  Imported digests are recorded as legacy_digest and are NOT verified\n");
    o.push_str("  against content. Re-run `skillguard lock` after verifying on disk.\n\n");
    emit(cli, &o)?;
    Ok(exit::OK)
}

fn run_diff(paths: &[PathBuf], strict: bool, cli: &Cli) -> Result<i32, String> {
    let outcomes = scan_all(paths)?;
    let mut o = String::from("\n  SkillGuard diff - declared permissions vs observed behaviour\n");
    let mut blocking_total = 0usize;

    for out in &outcomes {
        o.push_str(&format!("\n  {}\n", out.skill_name));
        o.push_str(&skillguard::permissions::render(&out.diff));
        blocking_total += out.diff.blocking().len();
    }

    o.push_str("  Undeclared behaviour is the finding that matters: a skill doing\n");
    o.push_str("  something it never declared is a skill whose author is not in control.\n\n");

    emit(cli, &o)?;

    if strict && blocking_total > 0 {
        Ok(exit::FINDINGS)
    } else {
        Ok(exit::OK)
    }
}

fn run_adopt(paths: &[PathBuf], dry_run: bool, cli: &Cli) -> Result<i32, String> {
    let targets = resolve_targets(paths)?;
    let mut o = String::from("\n  SkillGuard adopt - derive permissions from observed behaviour\n");

    for t in &targets {
        let out = scan_skill(t);
        let block = skillguard::permissions::to_yaml(&out.declared_from_observed());

        if dry_run {
            o.push_str(&format!("\n  {}\n{block}", out.skill_name));
            continue;
        }

        match adopt_into_skill_md(t, &block) {
            Ok(action) => o.push_str(&format!("\n  {}  {action}\n", out.skill_name)),
            Err(e) => o.push_str(&format!("\n  {}  skipped: {e}\n", out.skill_name)),
        }
    }

    if !dry_run {
        o.push_str("\n  Review the block before committing it. It describes what the skill\n");
        o.push_str("  does today, not what it should do.\n");
    }
    o.push('\n');

    emit(cli, &o)?;
    Ok(exit::OK)
}

/// Insert or replace the `permissions:` block in a SKILL.md frontmatter.
///
/// An existing block is replaced rather than duplicated, and `adopt` is
/// idempotent: running it twice produces the same file.
fn adopt_into_skill_md(root: &std::path::Path, block: &str) -> Result<String, String> {
    let skill_md = root.join("SKILL.md");
    let src =
        std::fs::read_to_string(&skill_md).map_err(|e| format!("cannot read SKILL.md: {e}"))?;
    let split = skillguard::parser::split_frontmatter(&src);

    let Some((yaml, _)) = &split.frontmatter else {
        return Err(
            "no YAML frontmatter to extend; a skill without frontmatter has nowhere to declare"
                .to_owned(),
        );
    };

    // Drop any existing permissions block from the YAML, then append the new one.
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

    let mut new_yaml = String::new();
    for l in &kept {
        new_yaml.push_str(l);
        new_yaml.push('\n');
    }
    if !new_yaml.is_empty() {
        new_yaml.push('\n');
    }
    new_yaml.push_str(block);

    let body = split.body.trim_start_matches('\n');
    let out = if body.trim().is_empty() {
        format!("---\n{new_yaml}---\n")
    } else {
        format!("---\n{new_yaml}---\n\n{body}")
    };

    std::fs::write(&skill_md, out).map_err(|e| format!("cannot write SKILL.md: {e}"))?;
    Ok("wrote permissions block".to_owned())
}

/// The nearest ancestor directory (including the file's own directory) that
/// contains a `SKILL.md`.
fn enclosing_skill(file: &std::path::Path) -> Option<PathBuf> {
    let mut dir = file.parent();
    while let Some(d) = dir {
        if d.join("SKILL.md").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

/// Resolve user input to a list of skill directories.
fn resolve_targets(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        if !p.exists() {
            return Err(format!("path does not exist: {}", p.display()));
        }
        if p.is_file() {
            // Accept a SKILL.md, or *any* file inside a skill. pre-commit hands
            // hooks the changed files, and a script change must re-scan its
            // skill even when SKILL.md did not change. This also makes
            // `skillguard scan scripts/setup.sh` do the obvious thing.
            match enclosing_skill(p) {
                Some(dir) => out.push(dir),
                None => {
                    return Err(format!(
                        "not a skill: {} (no SKILL.md in it or any parent directory)",
                        p.display()
                    ))
                }
            }
            continue;
        }
        let found = walk::discover_skill_dirs(p);
        if found.is_empty() {
            return Err(format!(
                "no SKILL.md found in {} (is this a skill directory?)",
                p.display()
            ));
        }
        out.extend(found);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn scan_all(paths: &[PathBuf]) -> Result<Vec<ScanOutcome>, String> {
    let targets = resolve_targets(paths)?;
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        // A single unreadable skill must not abort the whole run; it becomes a
        // report with a note. Phase 0 depends on this.
        out.push(scan::scan_skill(&t));
    }
    Ok(out)
}

fn emit(cli: &Cli, body: &str) -> Result<(), String> {
    match &cli.output {
        Some(p) => {
            std::fs::write(p, body).map_err(|e| format!("cannot write {}: {e}", p.display()))
        }
        None => {
            let stdout = std::io::stdout();
            let mut h = stdout.lock();
            h.write_all(body.as_bytes())
                .and_then(|()| h.flush())
                .map_err(|e| format!("cannot write to stdout: {e}"))
        }
    }
}

fn run_scan(
    paths: &[PathBuf],
    format: Format,
    fail_on: &str,
    list_rules: bool,
    cli: &Cli,
    color: bool,
) -> Result<i32, String> {
    if list_rules {
        return run_rules(format, cli, color);
    }

    let threshold = Severity::parse(fail_on).ok_or_else(|| {
        format!(
            "invalid --fail-on value {fail_on:?}; expected one of info, low, medium, high, critical"
        )
    })?;

    let outcomes = scan_all(paths)?;
    // Rule-level suppression is applied here, once, so every output format
    // agrees about what is in the report.
    let mut reports = Vec::with_capacity(outcomes.len());
    for out in &outcomes {
        let policy = match &out.root {
            Some(dir) => policy_for_dir(dir)?,
            None => skillguard::policy::Policy::new(),
        };
        let mut filtered = out.clone();
        filtered.findings = policy.apply_ignores(filtered.findings);
        reports.push(SkillReport::from_outcome(&filtered));
    }
    let report = Report::new(reports);

    let body = match format {
        Format::Text => skillguard::report::to_text_with(&report, color),
        other => other_emit(&report, other),
    };
    emit(cli, &body)?;

    if report.findings_at_or_above(threshold).is_empty() {
        Ok(exit::OK)
    } else {
        Ok(exit::FINDINGS)
    }
}

fn run_inspect(paths: &[PathBuf], format: Format, cli: &Cli, _color: bool) -> Result<i32, String> {
    let outcomes = scan_all(paths)?;
    let report = Report::new(outcomes.iter().map(SkillReport::from_outcome).collect());

    // Inspect prints capabilities only: no findings, no verdict.
    let mut o = String::new();
    for s in &report.skills {
        let d: &dyn Fn(&mut String) = &mut |o: &mut String| {
            o.push_str(&format!("\n  {}\n", s.name));
            if let Some(d) = &s.description {
                o.push_str(&format!(
                    "    description: {}\n",
                    text::truncate_chars(d, 100)
                ));
            }
            o.push_str(&format!(
                "    declared permissions: {}\n",
                s.declared_permissions_raw
                    .as_deref()
                    .map(|d| text::truncate_chars(d, 100))
                    .unwrap_or_else(|| "none".to_owned())
            ));
            o.push_str(&format!(
                "    license: declared={} file={}\n",
                s.license_declared.as_deref().unwrap_or("none"),
                if s.license_file_found { "yes" } else { "no" }
            ));
            let c = &s.capabilities;
            o.push_str("    observed capabilities:\n");
            if c.is_empty() {
                o.push_str("      none\n");
            } else {
                if !c.network_outbound.is_empty() {
                    o.push_str(&format!(
                        "      network.outbound: {}\n",
                        c.network_outbound.join(", ")
                    ));
                }
                if !c.shell_execute.is_empty() {
                    o.push_str(&format!(
                        "      shell.execute: {}\n",
                        c.shell_execute.join(", ")
                    ));
                }
                if !c.filesystem_read.is_empty() {
                    o.push_str(&format!(
                        "      filesystem.read: {}\n",
                        c.filesystem_read.join(", ")
                    ));
                }
                if !c.filesystem_write.is_empty() {
                    o.push_str(&format!(
                        "      filesystem.write: {}\n",
                        c.filesystem_write.join(", ")
                    ));
                }
                if !c.package_install.is_empty() {
                    o.push_str(&format!(
                        "      package_install: {}\n",
                        c.package_install.join(", ")
                    ));
                }
                if c.secrets_read {
                    o.push_str("      secrets.read: true\n");
                }
            }
            if s.dependencies.is_empty() {
                o.push_str("    dependencies: none\n");
            } else {
                o.push_str(&format!("    dependencies ({}):\n", s.dependencies.len()));
                for d in s.dependencies.iter().take(200) {
                    o.push_str(&format!(
                        "      {}:{} {}\n",
                        d.ecosystem,
                        d.name,
                        d.version_spec.as_deref().unwrap_or("")
                    ));
                }
                if s.dependencies.len() > 200 {
                    o.push_str(&format!(
                        "      ... and {} more\n",
                        s.dependencies.len() - 200
                    ));
                }
            }
            o.push('\n');
        };
        d(&mut o);
    }

    if format == Format::Text {
        o.insert_str(
            0,
            "\n  SkillGuard inspect - capabilities only, no judgement\n",
        );
    }
    emit(cli, &o)?;
    Ok(exit::OK)
}

fn other_emit(report: &Report, format: Format) -> String {
    match format {
        Format::Text => skillguard::report::to_text(report),
        Format::Json => skillguard::report::to_json(report),
        Format::Sarif => skillguard::report::to_sarif(report),
        Format::Markdown => skillguard::report::to_markdown(report),
    }
}

fn run_rules(format: Format, cli: &Cli, color: bool) -> Result<i32, String> {
    let cat = skillguard::scan::rules::catalogue();
    let body = match format {
        Format::Text => {
            let mut o = String::from("\n  SkillGuard rule catalogue\n\n");
            let mut by_sev: std::collections::BTreeMap<&str, Vec<_>> = Default::default();
            for e in &cat {
                by_sev.entry(e.severity.as_str()).or_default().push(e);
            }
            for (sev, rules) in by_sev.iter().rev() {
                o.push_str(&format!("  {sev} ({})\n", rules.len()));
                for r in rules {
                    o.push_str(&format!(
                        "    {:<32} {}\n",
                        r.id,
                        text::truncate_chars(r.message, 78)
                    ));
                }
                o.push('\n');
            }
            let _ = color;
            o.push_str(&format!("  {} rules total\n\n", cat.len()));
            o
        }
        Format::Json => {
            let v: Vec<serde_json::Value> = cat
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "severity": e.severity.as_str(),
                        "capability": e.capability,
                        "message": e.message,
                        "remediation": e.remediation,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&serde_json::json!({
                "ruleSetVersion": skillguard::RULE_SET_VERSION,
                "count": cat.len(),
                "rules": v,
            }))
            .unwrap_or_else(|_| "{}".to_owned())
        }
        Format::Markdown => {
            // Generated by `skillguard rules --format markdown`. CI regenerates it
            // and fails if the committed docs/RULES.md drifts from the code
            // (issue #4), so the columns here are the contract for that file.
            let mut o = String::from(
                "| rule | severity | capability | what it catches | how to fix it | how to silence it |\n\
                 |---|---|---|---|---|---|\n",
            );
            for e in &cat {
                let cell = |s: &str| s.replace('|', "\\|");
                o.push_str(&format!(
                    "| `{}` | {} | {} | {} | {} | `findings.ignore: [\"{}\"]` |\n",
                    e.id,
                    e.severity.as_str(),
                    if e.capability.is_empty() {
                        "-"
                    } else {
                        e.capability
                    },
                    cell(e.message),
                    cell(e.remediation),
                    e.id
                ));
            }
            o
        }
        Format::Sarif => {
            // SARIF for a catalogue is not meaningful; emit an empty valid doc.
            skillguard::report::to_sarif(&Report::new(vec![]))
        }
    };
    emit(cli, &body)?;
    Ok(exit::OK)
}

/// Phase 0 corpus driver. Thin CLI over `skillguard::corpus`; all the logic
/// (and its tests) live in the library so the pipeline is usable from Rust too.
fn run_corpus(command: &CorpusCommand, cli: &Cli) -> Result<i32, String> {
    use skillguard::corpus;

    match command {
        CorpusCommand::Index {
            source,
            tree,
            layer,
            source_prefix,
            out,
        } => index_into(source, tree.as_ref(), layer, source_prefix, out, cli),

        CorpusCommand::Fetch {
            from_dir,
            tree,
            layer,
            source_prefix,
            out,
        } => index_into(from_dir, tree.as_ref(), layer, source_prefix, out, cli),

        CorpusCommand::Scan {
            manifest,
            tree,
            out,
            cache,
        } => {
            let entries = corpus::read_manifest(manifest)?;
            let cache_path = cache
                .clone()
                .unwrap_or_else(|| out.with_extension("cache.json"));
            let mut c = corpus::load_cache(&cache_path)?;
            let records = corpus::scan_manifest(&entries, tree, &mut c);
            corpus::write_records(out, &records)?;
            corpus::save_cache(&cache_path, &c)?;

            let scanned = records.iter().filter(|r| r.is_scanned()).count();
            let failed = records.len() - scanned;
            let mut o = format!(
                "\n  SkillGuard corpus scan\n    scanned {scanned}\n    failed  {failed}\n    output  {}\n",
                out.display()
            );
            for r in records.iter().filter(|r| !r.is_scanned()).take(20) {
                o.push_str(&format!(
                    "      {} - {}\n",
                    r.source_id,
                    r.reason.as_deref().unwrap_or("unknown")
                ));
            }
            if failed > 20 {
                o.push_str(&format!("      ... and {} more\n", failed - 20));
            }
            o.push('\n');
            emit(cli, &o)?;
            // A failed entry is recorded, not fatal: one unreadable skill must
            // not abort a 100,000-skill batch.
            Ok(exit::OK)
        }

        CorpusCommand::Stats {
            findings,
            by,
            format,
        } => {
            let records = corpus::read_records(findings)?;
            let dims: Vec<&str> = by
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let s = corpus::stats(&records, &dims);
            let body = match format {
                Format::Json => serde_json::to_string_pretty(&s)
                    .map_err(|e| format!("cannot serialise stats: {e}"))?,
                _ => corpus::report_markdown(&s, skillguard::RULE_SET_VERSION, &[]),
            };
            emit(cli, &body)?;
            Ok(exit::OK)
        }

        CorpusCommand::Report {
            findings,
            gold,
            out,
        } => {
            let records = corpus::read_records(findings)?;
            let dims: Vec<&str> = corpus::DEFAULT_DIMENSIONS.to_vec();
            let s = corpus::stats(&records, &dims);
            let scores = match gold {
                Some(path) => corpus::score(&corpus::read_gold(path)?),
                None => Vec::new(),
            };
            let body = corpus::report_markdown(&s, skillguard::RULE_SET_VERSION, &scores);
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                }
            }
            std::fs::write(out, &body)
                .map_err(|e| format!("cannot write {}: {e}", out.display()))?;
            emit(cli, &format!("\n  wrote {}\n\n", out.display()))?;
            Ok(exit::OK)
        }

        CorpusCommand::Reproduce { manifest, tree } => {
            let entries = corpus::read_manifest(manifest)?;
            let rep = corpus::reproduce(&entries, tree);
            let mut o = format!(
                "\n  SkillGuard corpus reproduce\n    checked        {}\n    matched        {}\n    missing digest {}\n    mismatched     {}\n",
                rep.checked,
                rep.matched,
                rep.missing_digest.len(),
                rep.mismatched.len()
            );
            for m in rep.mismatched.iter().take(20) {
                o.push_str(&format!("      {m}\n"));
            }
            o.push('\n');
            emit(cli, &o)?;
            Ok(if rep.ok() { exit::OK } else { exit::INTEGRITY })
        }
    }
}

/// The GOLD labelling view: normalized text and line numbers only.
///
/// Deliberately emits no rule output. If an annotator sees what the scanner
/// found, they agree with it, and the kappa that is supposed to make the labels
/// credible measures anchoring instead of agreement (research/PROTOCOL.md §4.3).
fn run_labeling(paths: &[PathBuf], cli: &Cli) -> Result<i32, String> {
    let targets = resolve_targets(paths)?;
    let mut o = String::from(
        "\n  SkillGuard labeling view - normalized text and line numbers, no rule output\n",
    );

    for t in &targets {
        o.push_str(&format!("\n  == {} ==\n", t.display()));
        let walked = walk::walk_skill(t);
        for f in &walked.files {
            if !f.scanned {
                o.push_str(&format!(
                    "  {}: SKIPPED ({})\n",
                    f.rel,
                    f.note.as_deref().unwrap_or("")
                ));
                continue;
            }
            let Ok(src) = std::str::from_utf8(&f.bytes) else {
                continue;
            };
            let norm = skillguard::text::normalize_file(src, walk::limits::MAX_FILE_BYTES as usize);
            for l in &norm.lines {
                o.push_str(&format!(
                    "{}:{} | {}\n",
                    f.rel,
                    l.line,
                    text::sanitize_for_display(&l.norm)
                ));
            }
        }
    }

    emit(cli, &o)?;
    Ok(exit::OK)
}

/// Shared body of `corpus index` and `corpus fetch --from-dir`: the two differ
/// only in where the tree came from.
fn index_into(
    source: &std::path::Path,
    tree: Option<&PathBuf>,
    layer: &str,
    source_prefix: &str,
    out: &std::path::Path,
    cli: &Cli,
) -> Result<i32, String> {
    let tree = tree.cloned().unwrap_or_else(|| source.to_path_buf());
    let entries = skillguard::corpus::index_tree(source, &tree, layer, source_prefix)?;
    skillguard::corpus::write_manifest(out, &entries)?;
    emit(
        cli,
        &format!(
            "\n  SkillGuard corpus index\n    {} skill(s) -> {}\n\n",
            entries.len(),
            out.display()
        ),
    )?;
    Ok(exit::OK)
}
