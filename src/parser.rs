//! SKILL.md parsing.
//!
//! A skill is a Markdown file with optional YAML frontmatter. The format is an
//! open standard (agentskills.io, stewarded by the Agentic AI Foundation), so
//! the parser is deliberately permissive: it extracts what it recognises and
//! records what it could not parse rather than failing (docs/THREAT_MODEL.md T11).
//!
//! Frontmatter is located by byte offset, not by assuming `---` starts at
//! column 0 of a line that is preceded by nothing, so a file with a BOM or
//! leading whitespace still parses.

use crate::models::{ArtifactKind, Confidence, Dependency, Evidence, Finding, RuleId, Severity};
use std::collections::BTreeMap;

/// Split `SKILL.md` into frontmatter text and body, with line offsets.
pub struct Split {
    pub frontmatter: Option<(String, usize)>,
    pub body: String,
    pub body_start_line: usize,
}

/// Locate and cut the frontmatter block.
///
/// Returns `(raw_yaml, line_of_first_yaml_line)` when present. The body is
/// everything after the closing fence.
pub fn split_frontmatter(src: &str) -> Split {
    // Skip a UTF-8 BOM.
    let s = src.strip_prefix('\u{feff}').unwrap_or(src);

    let mut lines = s.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return Split {
            frontmatter: None,
            body: s.to_owned(),
            body_start_line: 1,
        };
    };

    if first.trim_end_matches(['\r', '\n']).trim() != "---" {
        return Split {
            frontmatter: None,
            body: s.to_owned(),
            body_start_line: 1,
        };
    }

    let mut yaml = String::new();
    let mut yaml_lines = 0usize;
    let mut closed = false;

    for line in lines {
        let t = line.trim_end_matches(['\r', '\n']).trim();
        if t == "---" || t == "..." {
            closed = true;
            break;
        }
        yaml.push_str(line);
        yaml_lines += 1;
    }

    if !closed {
        // Unterminated frontmatter: treat the whole file as body. An attacker
        // can hide payload this way, but mis-parsing it as YAML would be worse.
        return Split {
            frontmatter: None,
            body: s.to_owned(),
            body_start_line: 1,
        };
    }

    let body = body_from(s, yaml_lines);
    Split {
        frontmatter: Some((yaml, 2)),
        body,
        // Line 1 opens the fence, lines 2..=yaml_lines+1 hold YAML, line
        // yaml_lines+2 closes it, so the body starts on the next line.
        body_start_line: yaml_lines + 3,
    }
}

/// Slice everything after the frontmatter block.
fn body_from(src: &str, yaml_lines: usize) -> String {
    // Line 1 is the opening fence, lines 2..=yaml_lines+1 are YAML, and
    // line yaml_lines+2 is the closing fence. The body starts after it.
    let skip = yaml_lines + 2;
    let mut seen = 0usize;
    let mut byte = 0usize;
    for line in src.split_inclusive('\n') {
        seen += 1;
        byte += line.len();
        if seen >= skip {
            return src[byte..].to_owned();
        }
    }
    String::new()
}

/// Flatten YAML into `key -> value` pairs.
///
/// One level of nesting is enough for frontmatter. A nested block keeps its
/// **lines** joined by `\n` rather than concatenated, so a consumer can still
/// see where one nested key ended and the next began. Concatenating them was a
/// real bug: `network: {outbound: a}` followed by `shell: {execute: b}` becomes
/// the single line `network: outbound: a shell: execute: b`, which is
/// unrecoverable.
pub fn flatten_frontmatter(yaml: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut current_key: Option<String> = None;
    let mut nested: Vec<(String, String)> = Vec::new();

    for raw in yaml.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim_end();

        if indent == 0 {
            if let Some(k) = current_key.take() {
                let v = nested
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                if !v.is_empty() {
                    out.insert(k, v);
                }
            }
            nested.clear();
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().trim_matches('"').to_owned();
                let v = v.trim().to_owned();
                if v.is_empty() {
                    current_key = Some(k);
                } else {
                    out.insert(k, strip_quotes(&v));
                }
            }
        } else if let Some(k) = current_key.as_ref() {
            nested.push((k.clone(), line.trim().to_owned()));
        }
    }
    if let Some(k) = current_key.take() {
        let v = nested
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if !v.is_empty() {
            out.insert(k, v);
        }
    }
    out
}

fn strip_quotes(v: &str) -> String {
    v.trim()
        .trim_start_matches(['[', '{'])
        .trim_end_matches([']', '}'])
        .trim()
        .trim_matches(['"', '\''])
        .to_owned()
}

/// Parse a YAML dependency list such as `[a, b]` or a block list.
fn parse_dep_list(raw: &str) -> Vec<String> {
    let t = raw.trim().trim_start_matches('[').trim_end_matches(']');
    t.split(',')
        .map(|s| s.trim().trim_matches(['"', '\'']).to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract dependencies from manifests and frontmatter.
pub fn parse_dependencies(kind: ArtifactKind, rel: &str, text: &str) -> Vec<Dependency> {
    let mut out: Vec<Dependency> = Vec::new();
    let name = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();

    if kind == ArtifactKind::Manifest {
        match name.as_str() {
            "package.json" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                    for (field, eco) in [
                        ("dependencies", "npm"),
                        ("devDependencies", "npm"),
                        ("optionalDependencies", "npm"),
                    ] {
                        if let Some(obj) = v.get(field).and_then(|x| x.as_object()) {
                            for (k, spec) in obj {
                                out.push(Dependency {
                                    ecosystem: eco.to_owned(),
                                    name: k.clone(),
                                    version_spec: spec.as_str().map(str::to_owned),
                                });
                            }
                        }
                    }
                }
            }
            "requirements.txt" | "requirements-dev.txt" | "pipfile" => {
                for line in text.lines() {
                    let l = line.trim();
                    if l.is_empty() || l.starts_with('#') || l.starts_with('-') {
                        continue;
                    }
                    // `requests>=2.31.0`, `pandas ; python_version<"3.11"`,
                    // `numpy[extra]==1.26.0`: the name ends at the first
                    // separator, whichever comes first.
                    let name: String = l
                        .chars()
                        .take_while(|c| {
                            c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.'
                        })
                        .collect();
                    let rest = l[name.len()..].trim();
                    let version_spec = rest
                        .split_whitespace()
                        .find(|w| {
                            w.starts_with('=')
                                || w.starts_with('>')
                                || w.starts_with('<')
                                || w.starts_with('~')
                                || w.starts_with('!')
                                || w.starts_with(';')
                        })
                        .map(str::to_owned);
                    out.push(Dependency {
                        ecosystem: "pypi".to_owned(),
                        name,
                        version_spec,
                    });
                }
            }
            "pyproject.toml" | "cargo.toml" => {
                if let Ok(v) = text.parse::<toml::Value>() {
                    let eco = if name == "cargo.toml" {
                        "crates.io"
                    } else {
                        "pypi"
                    };
                    // PEP 621 puts dependencies under [project]; Cargo puts them
                    // in a [dependencies] table. Handle both shapes.
                    if let Some(arr) = v
                        .get("project")
                        .and_then(|p| p.get("dependencies"))
                        .and_then(|d| d.as_array())
                    {
                        for item in arr {
                            let s = item.as_str().unwrap_or("");
                            let (n, spec) = split_spec(s);
                            out.push(Dependency {
                                ecosystem: eco.to_owned(),
                                name: n,
                                version_spec: spec,
                            });
                        }
                    }
                    if let Some(deps) = v.get("dependencies").and_then(|d| d.as_table()) {
                        for (k, val) in deps {
                            let spec = match val {
                                toml::Value::String(s) => Some(s.clone()),
                                toml::Value::Table(t) => {
                                    t.get("version").and_then(|x| x.as_str()).map(str::to_owned)
                                }
                                _ => None,
                            };
                            out.push(Dependency {
                                ecosystem: eco.to_owned(),
                                name: k.clone(),
                                version_spec: spec,
                            });
                        }
                    }
                }
            }
            "go.mod" => {
                for line in text.lines() {
                    let l = line.trim();
                    for kw in ["require (", "require "] {
                        if let Some(rest) = l.strip_prefix(kw) {
                            let entry = rest.trim_end_matches(')');
                            let mut it = entry.split_whitespace();
                            if let Some(n) = it.next() {
                                out.push(Dependency {
                                    ecosystem: "go".to_owned(),
                                    name: n.to_owned(),
                                    version_spec: it.next().map(str::to_owned),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out.retain(|d| !d.name.is_empty());
    out
}

fn split_spec(s: &str) -> (String, Option<String>) {
    match s.find(['>', '<', '=', '~', '!']) {
        Some(i) => (s[..i].trim().to_owned(), Some(s[i..].trim().to_owned())),
        None => (s.trim().to_owned(), None),
    }
}

/// Detect a frontmatter permission block without interpreting it.
///
/// Phase 2 parses the structure. Phase 1 only needs to know it exists and to
/// re-scan it as text, so that a permission declaration cannot smuggle payload.
pub fn declared_permissions_raw(fm: &BTreeMap<String, String>) -> Option<String> {
    for key in [
        "permissions",
        "skillguard.permissions",
        "allowed-tools",
        "allowed_tools",
    ] {
        if let Some(v) = fm.get(key) {
            if !v.trim().is_empty() {
                return Some(format!("{key}:\n{v}"));
            }
        }
    }
    None
}

/// Parse the skill's identity fields. Unparseable frontmatter yields a finding
/// rather than an error (invariant S7).
pub fn parse_identity(
    fm_res: Result<BTreeMap<String, String>, String>,
    rel: &str,
) -> (BTreeMap<String, String>, Option<Finding>) {
    match fm_res {
        Ok(m) => (m, None),
        Err(e) => (
            BTreeMap::new(),
            Some(Finding::new(
                RuleId::from("PARSE_FAILED"),
                Severity::Info,
                Confidence::High,
                rel,
                format!("frontmatter could not be parsed: {e}"),
                vec![Evidence {
                    line: 1,
                    text: crate::text::truncate_chars(&e, 200),
                    secondary: None,
                    note: Some("parser".to_owned()),
                }],
            )),
        ),
    }
}

/// Extract a `dependencies:` list from frontmatter, if present.
pub fn frontmatter_dependencies(fm: &BTreeMap<String, String>) -> Vec<Dependency> {
    let mut out = Vec::new();
    for key in ["dependencies", "requires", "tools"] {
        if let Some(v) = fm.get(key) {
            for name in parse_dep_list(v) {
                out.push(Dependency {
                    ecosystem: "declared".to_owned(),
                    name,
                    version_spec: None,
                });
            }
        }
    }
    out
}

/// License identifiers we recognize. SPDX expression validation is Phase 3;
/// here we only compare the declared string against the file that exists.
pub fn license_declared(fm: &BTreeMap<String, String>) -> Option<String> {
    fm.get("license")
        .map(|s| s.trim().trim_matches('"').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = "---\nname: pdf-tools\ndescription: Work with PDFs.\nlicense: MIT\n---\n\n# PDF Tools\n\nUse `pdftotext`.\n";

    #[test]
    fn splits_frontmatter() {
        let s = split_frontmatter(SIMPLE);
        let (yaml, _) = s.frontmatter.expect("frontmatter");
        assert!(yaml.contains("name: pdf-tools"));
        assert!(s.body.contains("PDF Tools"));
        assert_eq!(s.body_start_line, 6);
    }

    #[test]
    fn parses_without_frontmatter() {
        let s = split_frontmatter("# Just markdown\n\nhello\n");
        assert!(s.frontmatter.is_none());
        assert_eq!(s.body_start_line, 1);
    }

    #[test]
    fn tolerates_bom() {
        let src = format!("\u{feff}{SIMPLE}");
        let s = split_frontmatter(&src);
        assert!(s.frontmatter.is_some());
    }

    #[test]
    fn unterminated_frontmatter_is_body() {
        let s = split_frontmatter("---\nname: x\n\nstill going\n");
        assert!(s.frontmatter.is_none(), "must not parse unterminated block");
        assert!(s.body.contains("still going"));
    }

    #[test]
    fn flattens_top_level_and_nested() {
        let m =
            flatten_frontmatter("name: a\npermissions:\n  network: outbound\n  shell: python\n");
        assert_eq!(m.get("name").map(String::as_str), Some("a"));
        let p = m.get("permissions").expect("nested block");
        assert!(p.contains("network"));
        assert!(p.contains("python"));
    }

    #[test]
    fn reads_permissions_block() {
        let m = flatten_frontmatter("name: a\npermissions:\n  network: api.example.com\n");
        assert!(declared_permissions_raw(&m).is_some());
    }

    #[test]
    fn parses_package_json_deps() {
        let deps = parse_dependencies(
            ArtifactKind::Manifest,
            "package.json",
            r#"{"dependencies":{"left-pad":"^1.3.0"},"devDependencies":{"jest":"^29"}}"#,
        );
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "left-pad" && d.ecosystem == "npm"));
    }

    #[test]
    fn parses_requirements_txt() {
        let deps = parse_dependencies(
            ArtifactKind::Manifest,
            "requirements.txt",
            "# comment\nrequests>=2.31.0\npandas\n-r other.txt\nnumpy ==1.26.0\n",
        );
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["requests", "pandas", "numpy"]);
        let r = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(r.version_spec.as_deref(), Some(">=2.31.0"));
    }

    #[test]
    fn parses_cargo_toml() {
        let deps = parse_dependencies(
            ArtifactKind::Manifest,
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\ntokio = { version = \"1.40\" }\n",
        );
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| d.ecosystem == "crates.io"));
    }

    #[test]
    fn identity_of_malformed_frontmatter_yields_finding() {
        let (m, f) = parse_identity(Err("bad indent".to_owned()), "SKILL.md");
        assert!(m.is_empty());
        let f = f.expect("finding");
        assert_eq!(f.rule.as_str(), "PARSE_FAILED");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn body_line_numbers_are_exact() {
        let s = split_frontmatter(SIMPLE);
        // Body starts at line 6 per the frontmatter, and the body text is
        // re-normalized by the scanner with that offset applied.
        assert_eq!(s.body_start_line, 6);
        assert!(s.body.starts_with("\n# PDF Tools"));
    }
}
