//! SkillGuard CLI.
//!
//! Exit codes are part of the contract (see `skillguard::exit`):
//! 0 clean · 1 findings at/above `--fail-on` · 2 integrity · 3 usage · 4 internal.

use clap::{Parser, Subcommand};
use skillguard::exit;
use skillguard::models::Severity;
use skillguard::report::{Format, Report, SkillReport};
use skillguard::scan::{self, scan_skill, ScanOutcome};
use skillguard::text;
use skillguard::walk;
use std::io::Write;
use std::path::PathBuf;
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

    /// Print the rule catalogue.
    Rules {
        #[arg(long, short, default_value = "text", value_enum)]
        format: Format,
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
        Command::Inspect { paths, format } => run_inspect(paths, *format, &cli, color),
        Command::Diff { paths, strict } => run_diff(paths, *strict, &cli),
        Command::Adopt { paths, dry_run } => run_adopt(paths, *dry_run, &cli),
        Command::Rules { format } => run_rules(*format, &cli, color),
    };

    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("skillguard: {e}");
            ExitCode::from(exit::USAGE as u8)
        }
    }
}

fn run_diff(paths: &[PathBuf], strict: bool, cli: &Cli) -> Result<i32, String> {
    let outcomes = scan_all(paths)?;
    let mut o = String::from("\n  SkillGuard diff · declared permissions vs observed behaviour\n");
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
    let mut o = String::from("\n  SkillGuard adopt · derive permissions from observed behaviour\n");

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

/// Resolve user input to a list of skill directories.
fn resolve_targets(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        if !p.exists() {
            return Err(format!("path does not exist: {}", p.display()));
        }
        if p.is_file() {
            // A single SKILL.md was named.
            if p.file_name().map(|n| n == "SKILL.md").unwrap_or(false) {
                if let Some(parent) = p.parent() {
                    out.push(parent.to_path_buf());
                }
            } else {
                return Err(format!("not a skill: {}", p.display()));
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
    let report = Report::new(outcomes.iter().map(SkillReport::from_outcome).collect());

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
                        "      … and {} more\n",
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
            "\n  SkillGuard inspect · capabilities only, no judgement\n",
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
            let mut o = String::from(
                "| rule | severity | capability | what it means |\n|---|---|---|---|\n",
            );
            for e in &cat {
                o.push_str(&format!(
                    "| `{}` | {} | {} | {} |\n",
                    e.id,
                    e.severity.as_str(),
                    if e.capability.is_empty() {
                        "-"
                    } else {
                        e.capability
                    },
                    e.message.replace('|', "\\|")
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
