//! Declared permissions vs observed capabilities.
//!
//! This is the differentiator: every other tool records what a skill *does*.
//! Android's insight is that a *declaration* is a contract the system can
//! check. Nobody applies that to skills yet, and arXiv:2606.03024 does it only
//! with an LLM and a runtime sandbox.
//!
//! # The precision problem, stated plainly
//!
//! A naive diff is useless, because most observations are not capabilities:
//!
//! * a URL in prose is documentation, not egress
//! * `~/.ssh` in a how-to guide is advice, not credential theft
//! * a `git` invocation in an example is not shell execution
//!
//! Two rules make the diff usable, and both are implemented here:
//!
//! 1. **Only executable artifacts produce observations.** Markdown is excluded
//!    upstream in [`crate::scan`]; this module never sees prose.
//! 2. **Declaration patterns are globs, observations are literals.** A skill
//!    declaring `./data/**` is not expected to enumerate every file under it.
//!
//! What survives both filters is a small set of high-confidence mismatches.
//! That is the whole design. See docs/MVP.md §4.

use crate::models::{Capability, DiffReport, Mismatch, MismatchKind, PermissionDecl, Severity};
use crate::text;
use globset::Glob;
use std::collections::BTreeSet;

/// Parse a `permissions:` block out of frontmatter.
///
/// Accepts both shapes that appear in the wild:
///
/// ```yaml
/// permissions:
///   network:
///     outbound: [api.example.com]
///   secrets:
///     access: false
/// ```
///
/// ```yaml
/// permissions:
///   network.outbound: api.example.com
///   shell.execute: [python, bash]
/// ```
fn as_decl(raw: &str) -> PermissionDecl {
    let mut d = PermissionDecl::default();
    let mut saw_any = false;

    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        // Strip a leading list marker such as `- `.
        let t = t.strip_prefix("- ").unwrap_or(t);
        let Some((key, value)) = split_kv(t) else {
            continue;
        };
        let key = normalize_key(&key);
        let values = parse_list(&value);
        if !values.is_empty() {
            saw_any = true;
        }
        match key.as_str() {
            "network.outbound" | "network" => d.network_outbound.extend(values),
            "network.deny" | "deny_domains" => {}
            "shell.execute" | "shell" | "shell.commands" => d.shell_execute.extend(values),
            "filesystem.read" => d.filesystem_read.extend(values),
            "filesystem.write" => d.filesystem_write.extend(values),
            "secrets.access" | "secrets" => {
                let v = value.trim().to_ascii_lowercase();
                d.secrets_access = match v.as_str() {
                    "false" | "no" | "none" | "deny" => Some(false),
                    "true" | "yes" | "allow" => Some(true),
                    _ => d.secrets_access,
                };
                saw_any = true;
            }
            "package_install" | "package.install" => d.package_install.extend(values),
            _ => {}
        }
    }

    d.declared = saw_any || !d.is_empty();
    d.normalized()
}

/// `network: {outbound: [...]}` nested form: the parent line carries no value,
/// so re-scan the raw text for `outbound:` style keys.
fn parse_nested(raw: &str) -> PermissionDecl {
    let mut d = as_decl(raw);
    if d.network_outbound.is_empty() || d.shell_execute.is_empty() {
        for line in raw.lines() {
            let t = line.trim();
            let Some((key, value)) = split_kv(t) else {
                continue;
            };
            let values = parse_list(&value);
            match normalize_key(&key).as_str() {
                "outbound" => d.network_outbound.extend(values),
                "execute" | "allow" => d.shell_execute.extend(values),
                "read" => d.filesystem_read.extend(values),
                "write" => d.filesystem_write.extend(values),
                _ => {}
            }
        }
    }
    d.declared = true;
    d.normalized()
}

/// Build a declaration from an already-parsed YAML frontmatter.
///
/// This is the authoritative path. The frontmatter has been through
/// `serde_yaml` by the time it gets here, so real YAML semantics apply —
/// including flow mappings like `network: {outbound: [a, b]}`, which no
/// line-based splitter can recover.
pub fn parse_yaml(fm: &serde_yaml::Value) -> PermissionDecl {
    let map = match fm.as_mapping() {
        Some(m) => m,
        None => return PermissionDecl::default(),
    };
    let get = |k: &str| -> Option<&serde_yaml::Value> {
        map.get(serde_yaml::Value::String(k.to_owned()))
    };

    for key in ["permissions", "skillguard.permissions"] {
        if let Some(v) = get(key) {
            let d = from_yaml_node(v);
            if !d.is_empty() {
                return d.normalized();
            }
        }
    }
    if let Some(v) = get("allowed-tools").or_else(|| get("allowed_tools")) {
        let d = from_allowed_tools(v);
        if !d.is_empty() {
            return d.normalized();
        }
    }
    PermissionDecl::default()
}

/// Interpret the body of a `permissions:` node.
///
/// Accepts both shapes seen in the wild: nested (`network: {outbound: [...]}`)
/// and flat dotted keys (`network.outbound: [...]`).
fn from_yaml_node(node: &serde_yaml::Value) -> PermissionDecl {
    let mut d = PermissionDecl::default();
    walk_permissions(node, &mut d, "");
    d.declared = true;
    d
}

fn walk_permissions(node: &serde_yaml::Value, d: &mut PermissionDecl, prefix: &str) {
    let Some(map) = node.as_mapping() else {
        return;
    };
    for (k, v) in map {
        let Some(key) = k.as_str() else { continue };
        let key = key.trim().to_ascii_lowercase().replace('_', ".");
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        // A boolean leaf is a declaration, not a list.
        if let Some(b) = v.as_bool() {
            if path.ends_with("secrets.access") || path == "secrets" {
                d.secrets_access = Some(b);
            }
            continue;
        }

        // A nested mapping recurses; its keys extend the path.
        if v.as_mapping().is_some() {
            walk_permissions(v, d, &path);
            continue;
        }

        let values = yaml_strings(v);
        if values.is_empty() {
            continue;
        }
        match path.as_str() {
            "network.outbound" | "network" | "outbound" => d.network_outbound.extend(values),
            "shell.execute" | "shell" | "shell.commands" | "execute" | "commands" => {
                d.shell_execute.extend(values);
            }
            "filesystem.read" | "filesystem.reads" | "read" => d.filesystem_read.extend(values),
            "filesystem.write" | "filesystem.writes" | "write" => {
                d.filesystem_write.extend(values);
            }
            "package.install" | "package_install" | "package.installs" | "package" => {
                d.package_install.extend(values);
            }
            _ => {}
        }
    }
}

fn yaml_strings(v: &serde_yaml::Value) -> Vec<String> {
    match v {
        serde_yaml::Value::Sequence(seq) => seq.iter().filter_map(scalar_string).collect(),
        serde_yaml::Value::String(s) => vec![s.trim().to_owned()],
        serde_yaml::Value::Number(n) => vec![n.to_string()],
        serde_yaml::Value::Bool(b) => vec![b.to_string()],
        _ => Vec::new(),
    }
}

fn scalar_string(v: &serde_yaml::Value) -> Option<String> {
    let s = match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    let t = s.trim().to_owned();
    if t.is_empty() || t == "~" || t == "null" {
        return None;
    }
    Some(t)
}

/// Claude Code style: a flat list of allowed tools.
fn from_allowed_tools(v: &serde_yaml::Value) -> PermissionDecl {
    let mut d = PermissionDecl::default();
    for tool in yaml_strings(v) {
        match tool.to_ascii_lowercase().as_str() {
            "bash" | "shell" => d.shell_execute.push("sh".to_owned()),
            "webfetch" | "websearch" => d.network_outbound.push("*".to_owned()),
            "read" => d.filesystem_read.push("./**".to_owned()),
            other => {
                if other.contains('.') {
                    d.network_outbound.push(other.to_owned());
                } else {
                    d.shell_execute.push(other.to_owned());
                }
            }
        }
    }
    d.declared = true;
    d
}

/// Build a declaration from a frontmatter map.
///
/// Fallback for callers that only have the flattened map (the flattener keeps
/// nested blocks on separate lines, so this recovers the common shapes).
pub fn parse_frontmatter(fm: &std::collections::BTreeMap<String, String>) -> PermissionDecl {
    for key in ["permissions", "skillguard.permissions"] {
        if let Some(raw) = fm.get(key) {
            if !raw.trim().is_empty() {
                return parse_nested(raw);
            }
        }
    }
    // Claude Code style: a flat list of allowed tools.
    if let Some(raw) = fm.get("allowed-tools").or_else(|| fm.get("allowed_tools")) {
        let mut d = PermissionDecl::default();
        for tool in parse_list(raw) {
            match tool.to_ascii_lowercase().as_str() {
                "bash" | "shell" => d.shell_execute.push("sh".to_owned()),
                "webfetch" | "websearch" => d.network_outbound.push("*".to_owned()),
                "read" => d.filesystem_read.push("./**".to_owned()),
                other => {
                    if other.contains('.') {
                        d.network_outbound.push(other.to_owned());
                    } else {
                        d.shell_execute.push(other.to_owned());
                    }
                }
            }
        }
        if !d.is_empty() {
            d.declared = true;
            return d.normalized();
        }
    }
    PermissionDecl::default()
}

fn split_kv(t: &str) -> Option<(String, String)> {
    let (k, v) = t.split_once(':')?;
    Some((k.trim().to_owned(), v.trim().to_owned()))
}

/// `network.outbound` and `network_outbound` both mean the same thing.
fn normalize_key(k: &str) -> String {
    k.trim()
        .trim_matches(['"', '\''])
        .to_ascii_lowercase()
        .replace(['_', ' '], ".")
}

/// Accept `[a, b]`, `a, b` and a bare single value.
///
/// Commas inside a nested list or map must not split, so bracket depth is
/// tracked. Splitting naively on every comma mangles `[[a, b], c]` into
/// `[a` and `b]`.
fn parse_list(v: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth: i32 = 0;
    for ch in v.chars() {
        match ch {
            '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth <= 0 => {
                push_item(&mut cur, &mut out);
            }
            _ => cur.push(ch),
        }
    }
    push_item(&mut cur, &mut out);
    out
}

fn push_item(cur: &mut String, out: &mut Vec<String>) {
    let item = cur
        .trim()
        .trim_matches(['"', '\'', '[', ']'])
        .trim()
        .to_owned();
    cur.clear();
    if item.is_empty() || item == "~" || item == "null" {
        return;
    }
    out.push(item);
}

/// Compare a declaration against observation.
///
/// `observed` must already be code-only (see the module docs).
pub fn diff(declared: &PermissionDecl, observed: &Capability) -> DiffReport {
    if declared.is_empty() {
        return DiffReport {
            no_declaration: true,
            mismatches: Vec::new(),
        };
    }
    let d = declared.normalized();
    let o = observed.normalized();
    let mut out = DiffReport::default();

    // ── network.outbound ──────────────────────────────────────────────────
    let allow_any = d.network_outbound.iter().any(|h| h == "*");
    for host in &o.network_outbound {
        if allow_any || d.network_outbound.iter().any(|p| host_matches(p, host)) {
            continue;
        }
        out.mismatches.push(Mismatch {
            kind: MismatchKind::UnderDeclared,
            capability: "network.outbound".to_owned(),
            detail: host.clone(),
            // Egress to an undeclared host is the single highest-value signal
            // this tool produces: it is how data leaves.
            severity: Severity::High,
        });
    }
    for host in &d.network_outbound {
        if host == "*" {
            continue;
        }
        if !o.network_outbound.iter().any(|h| host_matches(host, h)) {
            out.mismatches.push(Mismatch {
                kind: MismatchKind::OverDeclared,
                capability: "network.outbound".to_owned(),
                detail: host.clone(),
                severity: Severity::Info,
            });
        }
    }

    // ── shell.execute ─────────────────────────────────────────────────────
    let shell_any = d.shell_execute.iter().any(|c| c == "*" || c == "sh");
    for cmd in &o.shell_execute {
        // `sh` as a declaration covers the whole shell family; treating the
        // declaration literally would flag every single interpreter.
        let covered = shell_any
            || d.shell_execute.iter().any(|p| {
                p.eq_ignore_ascii_case(cmd)
                    || (p == "python" && cmd.starts_with("python"))
                    || (p == "node" && cmd.starts_with("node"))
                    || p == "*"
            });
        if covered {
            continue;
        }
        out.mismatches.push(Mismatch {
            kind: MismatchKind::UnderDeclared,
            capability: "shell.execute".to_owned(),
            detail: cmd.clone(),
            severity: Severity::Medium,
        });
    }

    // ── filesystem ────────────────────────────────────────────────────────
    for (label, observed_paths, declared_paths, sev) in [
        (
            "filesystem.read",
            &o.filesystem_read,
            &d.filesystem_read,
            Severity::Medium,
        ),
        (
            "filesystem.write",
            &o.filesystem_write,
            &d.filesystem_write,
            Severity::High,
        ),
    ] {
        let allow_any = declared_paths.iter().any(|p| p == "./**" || p == "**");
        for path in observed_paths {
            if allow_any || declared_paths.iter().any(|p| path_matches(p, path)) {
                continue;
            }
            out.mismatches.push(Mismatch {
                kind: MismatchKind::UnderDeclared,
                capability: label.to_owned(),
                detail: path.clone(),
                severity: sev,
            });
        }
    }

    // ── secrets ───────────────────────────────────────────────────────────
    match d.secrets_access {
        // The skill says it never touches secrets, and the code disagrees.
        Some(false) if o.secrets_read => out.mismatches.push(Mismatch {
            kind: MismatchKind::Conflicting,
            capability: "secrets.read".to_owned(),
            detail: "declared access: false, but the code reads secrets".to_owned(),
            severity: Severity::Critical,
        }),
        None if o.secrets_read => out.mismatches.push(Mismatch {
            kind: MismatchKind::UnderDeclared,
            capability: "secrets.read".to_owned(),
            detail: "the environment or a key store is read".to_owned(),
            severity: Severity::High,
        }),
        _ => {}
    }

    // ── package_install ───────────────────────────────────────────────────
    let pkg_any = d.package_install.iter().any(|p| p == "*");
    for pm in &o.package_install {
        let covered = pkg_any
            || d.package_install
                .iter()
                .any(|p| p.eq_ignore_ascii_case(pm) || p == "any");
        if covered {
            continue;
        }
        out.mismatches.push(Mismatch {
            kind: MismatchKind::UnderDeclared,
            capability: "package_install".to_owned(),
            detail: pm.clone(),
            severity: Severity::Medium,
        });
    }

    out.mismatches.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.capability.cmp(&b.capability))
            .then(a.detail.cmp(&b.detail))
    });
    out
}

/// Does a declared host pattern cover an observed host?
fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    if p == "*" {
        return true;
    }
    // A leading `.` or `*.` is a domain-suffix wildcard, not a glob.
    if let Some(suffix) = p.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if host == p {
        return true;
    }
    // A registrable-domain declaration covers its subdomains.
    if !p.contains('*') {
        let base = p.trim_start_matches('.');
        return host.ends_with(&format!(".{base}"));
    }
    glob_match(&p, host)
}

/// Does a declared path pattern cover an observed path?
fn path_matches(pattern: &str, path: &str) -> bool {
    let p = strip_dot_slash(pattern.trim());
    let target = strip_dot_slash(path.trim());
    if p == "**" || p == "*" {
        return true;
    }
    if glob_match(&p, &target) {
        return true;
    }
    // A directory declaration covers everything beneath it.
    let dir = p.trim_end_matches('/').trim_end_matches("/**");
    if !dir.is_empty() && target.starts_with(&format!("{dir}/")) {
        return true;
    }
    false
}

/// `./data/x` and `data/x` are the same path; authors write both.
fn strip_dot_slash(p: &str) -> String {
    p.replace('\\', "/").trim_start_matches("./").to_owned()
}

fn glob_match(pattern: &str, target: &str) -> bool {
    match Glob::new(pattern).ok().map(|g| g.compile_matcher()) {
        Some(m) => m.is_match(target),
        // An unparseable pattern covers nothing rather than everything. Failing
        // closed here would hide real egress; failing open would invent it.
        // Neither is acceptable, so it is reported as non-matching and the
        // author is left to fix their manifest.
        None => false,
    }
}

/// Render a declaration back to YAML frontmatter, for `skillguard adopt`.
///
/// Hostnames are sorted so re-running `adopt` produces an identical file.
pub fn to_yaml(decl: &PermissionDecl) -> String {
    let d = decl.normalized();
    let mut o = String::from("permissions:\n");
    if !d.network_outbound.is_empty() {
        o.push_str(&format!(
            "  network:\n    outbound: [{}]\n",
            d.network_outbound.join(", ")
        ));
    }
    if !d.shell_execute.is_empty() {
        o.push_str(&format!(
            "  shell:\n    execute: [{}]\n",
            d.shell_execute.join(", ")
        ));
    }
    if !d.filesystem_read.is_empty() {
        o.push_str(&format!(
            "  filesystem:\n    read: [{}]\n",
            d.filesystem_read.join(", ")
        ));
    }
    if !d.filesystem_write.is_empty() {
        o.push_str(&format!(
            "  filesystem:\n    write: [{}]\n",
            d.filesystem_write.join(", ")
        ));
    }
    o.push_str(&format!(
        "  secrets:\n    access: {}\n",
        d.secrets_access.unwrap_or(true)
    ));
    if !d.package_install.is_empty() {
        o.push_str(&format!(
            "  package_install: [{}]\n",
            d.package_install.join(", ")
        ));
    }
    o
}

/// Human-readable diff, for `skillguard diff`.
pub fn render(report: &DiffReport) -> String {
    if report.no_declaration {
        return String::from(
            "\n  no permission declaration found\n\n  \
             Add one with `skillguard adopt <path>`, which derives it from observed\n  \
             behaviour. Until then there is nothing to verify the skill against.\n",
        );
    }
    if report.mismatches.is_empty() {
        return String::from(
            "\n  declared permissions match observed behaviour\n\n  \
             Nothing the skill does is unaccounted for.\n",
        );
    }
    let mut o = String::new();
    o.push_str("\n  declared vs observed\n\n");
    let mut current = String::new();
    for m in &report.mismatches {
        if m.capability != current {
            current = m.capability.clone();
            o.push_str(&format!("    {current}\n"));
        }
        let tag = match m.kind {
            MismatchKind::UnderDeclared => "UNDECLARED",
            MismatchKind::OverDeclared => "unused     ",
            MismatchKind::Conflicting => "CONFLICT   ",
        };
        o.push_str(&format!(
            "      {} {}  {}\n",
            tag,
            m.severity,
            text::sanitize_for_display(&m.detail)
        ));
    }
    let blocking = report.blocking().len();
    o.push_str(&format!(
        "\n  {} mismatch(es), {} of them undeclared behaviour\n",
        report.mismatches.len(),
        blocking
    ));
    o.push('\n');
    o
}

/// All hosts a declaration permits, expanded from wildcards where possible.
pub fn declared_hosts(decl: &PermissionDecl) -> BTreeSet<String> {
    decl.network_outbound
        .iter()
        .filter(|h| !h.contains('*'))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(hosts: &[&str], shells: &[&str], secrets: bool) -> Capability {
        Capability {
            network_outbound: hosts.iter().map(|s| s.to_string()).collect(),
            shell_execute: shells.iter().map(|s| s.to_string()).collect(),
            secrets_read: secrets,
            ..Capability::default()
        }
    }

    /// Parse real YAML, the way the scanner does.
    fn decl(yaml: &str) -> PermissionDecl {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap_or(serde_yaml::Value::Null);
        parse_yaml(&v)
    }

    // ── parsing ───────────────────────────────────────────────────────────

    #[test]
    fn parses_nested_block() {
        let d = decl(
            "permissions:\n  network:\n    outbound:\n      - api.example.com\n      - cdn.example.com\n  shell:\n    execute:\n      - python\n  secrets:\n    access: false\n",
        );
        assert_eq!(
            d.network_outbound,
            vec!["api.example.com".to_owned(), "cdn.example.com".to_owned()],
            "{d:?}"
        );
        assert_eq!(d.shell_execute, vec!["python".to_owned()], "{d:?}");
        assert_eq!(d.secrets_access, Some(false), "{d:?}");
        assert!(d.declared);
    }

    #[test]
    fn parses_flow_mappings_and_bracket_lists() {
        // A line-based splitter cannot recover this; serde_yaml can.
        let d = decl(
            "permissions: {network: {outbound: [a.example.com, b.example.com]}, shell: {execute: [bash]}}",
        );
        assert_eq!(
            d.network_outbound,
            vec!["a.example.com".to_owned(), "b.example.com".to_owned()],
            "{d:?}"
        );
        assert_eq!(d.shell_execute, vec!["bash".to_owned()], "{d:?}");
    }

    #[test]
    fn parses_flat_dotted_keys() {
        let d = decl(
            "permissions:\n  network.outbound: api.example.com\n  shell.execute: [python, bash]\n  secrets.access: false\n",
        );
        assert_eq!(
            d.network_outbound,
            vec!["api.example.com".to_owned()],
            "{d:?}"
        );
        assert_eq!(
            d.shell_execute,
            vec!["bash".to_owned(), "python".to_owned()]
        );
        assert_eq!(d.secrets_access, Some(false));
    }

    #[test]
    fn parses_underscore_keys_and_package_install() {
        let d = decl(
            "permissions:\n  network:\n    outbound: a.example.com\n  package_install: [npm]\n",
        );
        assert_eq!(d.network_outbound, vec!["a.example.com".to_owned()]);
        assert_eq!(d.package_install, vec!["npm".to_owned()]);
    }

    #[test]
    fn parses_filesystem_read_and_write() {
        let d =
            decl("permissions:\n  filesystem:\n    read: ['./data/**']\n    write: ['./out/**']\n");
        assert_eq!(d.filesystem_read, vec!["./data/**".to_owned()], "{d:?}");
        assert_eq!(d.filesystem_write, vec!["./out/**".to_owned()], "{d:?}");
    }

    #[test]
    fn parses_allowed_tools_list() {
        let d = decl("allowed-tools: [Read, Bash, WebFetch]\n");
        assert!(d.declared, "{d:?}");
        assert!(d.shell_execute.contains(&"sh".to_owned()), "{d:?}");
        assert!(d.network_outbound.contains(&"*".to_owned()), "{d:?}");
    }

    #[test]
    fn no_permissions_key_yields_an_empty_declaration() {
        let d = decl("name: x\ndescription: does a thing\n");
        assert!(!d.declared);
        assert!(d.is_empty());
    }

    #[test]
    fn malformed_yaml_does_not_panic() {
        for bad in ["permissions: [unclosed", "\t- : :", "permissions:\n  - - -"] {
            let v: serde_yaml::Value = serde_yaml::from_str(bad).unwrap_or(serde_yaml::Value::Null);
            let d = parse_yaml(&v);
            let _ = d.normalized();
        }
    }

    #[test]
    fn fallback_flat_map_parser_also_works() {
        let fm = std::collections::BTreeMap::from([(
            "permissions".to_owned(),
            "network:\n  outbound: api.example.com\nshell:\n  execute: python".to_owned(),
        )]);
        let d = parse_frontmatter(&fm);
        assert_eq!(
            d.network_outbound,
            vec!["api.example.com".to_owned()],
            "{d:?}"
        );
        assert_eq!(d.shell_execute, vec!["python".to_owned()], "{d:?}");
    }

    // ── diffing ───────────────────────────────────────────────────────────

    #[test]
    fn no_declaration_yields_no_declaration_report() {
        let r = diff(
            &PermissionDecl::default(),
            &obs(&["a.example.com"], &[], false),
        );
        assert!(r.no_declaration);
        assert!(r.mismatches.is_empty());
    }

    #[test]
    fn undeclared_host_is_high_and_blocking() {
        let d = decl("permissions:\n  network:\n    outbound: [api.example.com]\n");
        let r = diff(
            &d,
            &obs(&["api.example.com", "evil.example.com"], &[], false),
        );
        let under = r.blocking();
        assert_eq!(under.len(), 1, "{:#?}", r);
        assert_eq!(under[0].detail, "evil.example.com");
        assert_eq!(under[0].severity, Severity::High);
    }

    #[test]
    fn declared_but_unused_is_informational() {
        let d =
            decl("permissions:\n  network:\n    outbound: [api.example.com, unused.example.com]\n");
        let r = diff(&d, &obs(&["api.example.com"], &[], false));
        assert_eq!(r.mismatches.len(), 1, "{:#?}", r);
        assert_eq!(r.mismatches[0].kind, MismatchKind::OverDeclared);
        assert_eq!(r.mismatches[0].severity, Severity::Info);
        assert!(r.blocking().is_empty(), "over-declaration never blocks");
    }

    #[test]
    fn secrets_false_with_secret_access_is_a_conflict() {
        let d = decl("permissions:\n  secrets:\n    access: false\n");
        let r = diff(&d, &obs(&[], &[], true));
        assert_eq!(r.mismatches.len(), 1, "{:#?}", r);
        assert_eq!(r.mismatches[0].kind, MismatchKind::Conflicting);
        assert_eq!(r.mismatches[0].severity, Severity::Critical);
    }

    #[test]
    fn undeclared_secret_access_is_under_declared() {
        let d = decl("permissions:\n  network:\n    outbound: []\n");
        let r = diff(&d, &obs(&[], &[], true));
        assert_eq!(r.mismatches.len(), 1, "{:#?}", r);
        assert_eq!(r.mismatches[0].kind, MismatchKind::UnderDeclared);
        assert_eq!(r.mismatches[0].capability, "secrets.read");
    }

    #[test]
    fn wildcard_declarations_cover_everything() {
        let d = decl(
            "permissions:\n  network:\n    outbound: ['*']\n  shell:\n    execute: ['*']\n  filesystem:\n    read: ['./**']\n  secrets:\n    access: true\n",
        );
        let mut o = obs(&["anything.example.net"], &["bash"], true);
        o.filesystem_read = vec!["/etc/hosts".to_owned()];
        let r = diff(&d, &o);
        assert!(r.mismatches.is_empty(), "{:#?}", r.mismatches);
    }

    #[test]
    fn undeclared_filesystem_read_is_flagged() {
        let d = decl("permissions:\n  filesystem:\n    read: ['./data/**']\n");
        let mut o = obs(&[], &[], false);
        o.filesystem_read = vec!["data/input.csv".to_owned(), "secrets/token".to_owned()];
        let r = diff(&d, &o);
        assert_eq!(r.blocking().len(), 1, "{:#?}", r);
        assert_eq!(r.blocking()[0].detail, "secrets/token");
    }

    #[test]
    fn undeclared_package_manager_is_flagged() {
        let d = decl("permissions:\n  network:\n    outbound: []\n");
        let mut o = obs(&[], &[], false);
        o.package_install = vec!["npm".to_owned()];
        let r = diff(&d, &o);
        assert_eq!(r.mismatches.len(), 1);
        assert_eq!(r.mismatches[0].capability, "package_install");
    }

    #[test]
    fn host_wildcards_and_subdomains() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "example.org"));
        assert!(host_matches("example.com", "api.example.com"));
        assert!(!host_matches("example.com", "notexample.com"));
    }

    #[test]
    fn path_globs_and_directory_prefixes() {
        assert!(path_matches("./data/**", "data/input.csv"));
        assert!(path_matches("./data/**", "./data/input.csv"));
        assert!(path_matches("/etc/hosts", "/etc/hosts"));
        assert!(path_matches("./data/", "data/x.csv"));
        assert!(!path_matches("./data/**", "secrets/x.csv"));
    }

    #[test]
    fn shell_declaration_of_sh_covers_the_family() {
        let d = decl("permissions:\n  shell:\n    execute: [sh]\n");
        let r = diff(&d, &obs(&[], &["bash", "python3"], false));
        assert!(
            r.mismatches.iter().all(|m| m.capability != "shell.execute"),
            "declaring `sh` must not flag bash: {:#?}",
            r.mismatches
        );
    }

    #[test]
    fn python_declaration_covers_python3() {
        let d = decl("permissions:\n  shell:\n    execute: [python]\n");
        let r = diff(&d, &obs(&[], &["python3"], false));
        assert!(r.mismatches.is_empty(), "{:#?}", r.mismatches);
    }

    #[test]
    fn diff_is_deterministic_and_ordered_by_severity() {
        let d = decl("permissions:\n  network:\n    outbound: [a.example.com]\n");
        let hosts = ["z.example.com", "b.example.com", "m.example.com"];
        let r1 = diff(&d, &obs(&hosts, &[], false));
        let r2 = diff(&d, &obs(&hosts, &[], false));
        assert_eq!(r1, r2, "the diff must be reproducible");

        let sevs: Vec<Severity> = r1.mismatches.iter().map(|m| m.severity).collect();
        let mut sorted = sevs.clone();
        sorted.sort_by(|x, y| y.cmp(x));
        assert_eq!(sevs, sorted, "most severe first");

        // Within one severity, details are ordered.
        let under: Vec<&str> = r1
            .mismatches
            .iter()
            .filter(|m| m.severity == Severity::High)
            .map(|m| m.detail.as_str())
            .collect();
        let mut sorted_under = under.clone();
        sorted_under.sort();
        assert_eq!(under, sorted_under);
        assert_eq!(
            under,
            vec!["b.example.com", "m.example.com", "z.example.com"]
        );
    }

    // ── rendering ─────────────────────────────────────────────────────────

    #[test]
    fn to_yaml_round_trips_through_the_yaml_parser() {
        let d = PermissionDecl {
            network_outbound: vec!["b.example.com".to_owned(), "a.example.com".to_owned()],
            shell_execute: vec!["python".to_owned()],
            filesystem_read: vec!["./data/**".to_owned()],
            secrets_access: Some(false),
            declared: true,
            ..PermissionDecl::default()
        };
        let yaml = to_yaml(&d);
        let back = decl(&yaml);
        assert_eq!(back, d.normalized(), "{yaml}");
    }

    #[test]
    fn to_yaml_is_stable_across_runs() {
        let d = PermissionDecl {
            network_outbound: vec!["b.example.com".to_owned(), "a.example.com".to_owned()],
            declared: true,
            ..PermissionDecl::default()
        };
        assert_eq!(to_yaml(&d), to_yaml(&d), "adopt must be idempotent");
    }

    #[test]
    fn render_explains_a_missing_declaration() {
        let r = diff(&PermissionDecl::default(), &obs(&[], &[], false));
        let out = render(&r);
        assert!(out.contains("no permission declaration"));
        assert!(out.contains("adopt"), "the message must say how to fix it");
    }

    #[test]
    fn render_is_safe_on_hostile_values() {
        let r = DiffReport {
            no_declaration: false,
            mismatches: vec![Mismatch {
                kind: MismatchKind::UnderDeclared,
                capability: "network.outbound".to_owned(),
                detail: "\u{1B}[31mevil.example.com".to_owned(),
                severity: Severity::High,
            }],
        };
        let out = render(&r);
        assert!(
            !out.contains('\u{1B}'),
            "invariant S5 at the render boundary"
        );
    }
}
