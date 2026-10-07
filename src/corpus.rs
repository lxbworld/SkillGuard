//! Phase 0 corpus driver (docs/PHASE0_CORPUS_STUDY.md, issue #1).
//!
//! This is a batch driver on top of the single-skill scanner, not a new engine.
//! It exists to make a large-scale measurement *reproducible*, which is the one
//! property that separates a corpus study from a blog post:
//!
//! * **Pinned commits only.** A manifest entry with a tag, a branch or a short
//!   SHA is refused, not warned about. A corpus pinned to a moving ref cannot be
//!   reproduced, so its numbers cannot be checked.
//! * **Byte-identical output.** Records are sorted by `source_id` and carry no
//!   timestamps. Scanning the same manifest twice produces the same JSONL.
//! * **Failure is visible.** A skill that cannot be read is recorded with a
//!   reason and counted in the denominators table; it is never dropped, because
//!   an invisible denominator is the easiest thing for a critic to attack.
//! * **Offline.** `scan`, `stats`, `report` and `reproduce` never open a socket.
//!   Only `index` reads the filesystem, and `fetch` from a network source is
//!   deliberately absent until collection is cleared (issue #5).
//!
//! Nothing here re-distributes payloads: the findings dataset records the rule,
//! file, line and severity, never the evidence text (protocol §3, R-2).

use crate::models::Severity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── manifest ──────────────────────────────────────────────────────────────

/// One skill in the corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Stable identifier, e.g. `local:skills/demo` or `github:o/r@<40hex>/demo`.
    pub source_id: String,
    /// Sampling layer: L1 registry, L2 disputed registry, L3 GitHub, L4 academic,
    /// L5 directory.
    pub layer: String,
    /// Full 40-hex commit. `None` means "not from a version-controlled source",
    /// which is allowed for a local index but makes the entry unreproducible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// `sha256:...` of the skill directory, as `sgdir-v1` computes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    /// Path to the skill, relative to the manifest's tree root.
    pub path: String,
    /// Stratification dimensions, already bucketed, e.g.
    /// `{"size":"8k_32k","scripts":"shell","declared":"none","license":"present"}`.
    #[serde(default)]
    pub stratum: BTreeMap<String, String>,
}

/// Read a JSONL manifest: one entry per line, blank lines and lines starting
/// with `#` ignored.
pub fn read_manifest(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read manifest {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let entry: ManifestEntry = serde_json::from_str(t)
            .map_err(|e| format!("{}:{}: invalid manifest entry: {e}", path.display(), i + 1))?;
        out.push(entry);
    }
    Ok(out)
}

/// Write a JSONL manifest, sorted by `source_id` so the file is diffable.
pub fn write_manifest(path: &Path, entries: &[ManifestEntry]) -> Result<(), String> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    let mut body = String::new();
    for e in &sorted {
        let line = serde_json::to_string(e).map_err(|e| format!("serialise manifest: {e}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, body).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── findings ──────────────────────────────────────────────────────────────

/// One finding, reduced to what may be published. No evidence text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CorpusFinding {
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub capability: String,
}

/// The result of scanning one manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecord {
    pub source_id: String,
    pub layer: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stratum: BTreeMap<String, String>,
    /// `scanned` or `failed`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CorpusFinding>,
}

impl ScanRecord {
    fn failed(entry: &ManifestEntry, reason: impl Into<String>) -> Self {
        ScanRecord {
            source_id: entry.source_id.clone(),
            layer: entry.layer.clone(),
            stratum: entry.stratum.clone(),
            status: "failed".to_owned(),
            content_digest: entry.content_digest.clone(),
            reason: Some(reason.into()),
            findings: Vec::new(),
        }
    }

    pub fn is_scanned(&self) -> bool {
        self.status == "scanned"
    }
}

/// A `content_digest -> findings` cache, so a re-run or a competitor comparison
/// costs nothing for already-scanned content (protocol §6.2).
pub type FindingCache = BTreeMap<String, Vec<CorpusFinding>>;

pub fn load_cache(path: &Path) -> Result<FindingCache, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            serde_json::from_str(&s).map_err(|e| format!("{}: invalid cache: {e}", path.display()))
        }
        Err(_) => Ok(FindingCache::new()),
    }
}

pub fn save_cache(path: &Path, cache: &FindingCache) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let body = serde_json::to_string(cache).map_err(|e| format!("serialise cache: {e}"))?;
    std::fs::write(path, body).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Scan every manifest entry against a tree, returning records sorted by
/// `source_id`.
///
/// `tree` is the directory the manifest's `path` fields are relative to. The
/// cache is keyed by content digest: identical content is scanned once.
pub fn scan_manifest(
    entries: &[ManifestEntry],
    tree: &Path,
    cache: &mut FindingCache,
) -> Vec<ScanRecord> {
    let mut records: Vec<ScanRecord> = Vec::with_capacity(entries.len());

    for e in entries {
        // A moving ref must be refused here as well as at fetch time: a
        // manifest can be hand-edited, and this is the last checkpoint before
        // its numbers enter the dataset.
        if let Some(commit) = &e.commit {
            if !crate::hash::is_full_commit(commit) {
                records.push(ScanRecord::failed(
                    e,
                    format!("commit is not a full 40-hex SHA: {commit:?}"),
                ));
                continue;
            }
        }

        let dir = tree.join(&e.path);
        if !dir.join("SKILL.md").is_file() {
            records.push(ScanRecord::failed(
                e,
                format!("no SKILL.md under {}", dir.display()),
            ));
            continue;
        }

        let digest = match crate::hash::digest_dir(&dir) {
            Ok((d, _)) => d,
            Err(reason) => {
                records.push(ScanRecord::failed(e, reason));
                continue;
            }
        };

        if let Some(want) = &e.content_digest {
            if want != digest.as_str() {
                records.push(ScanRecord::failed(
                    e,
                    format!(
                        "content digest mismatch: manifest {want}, tree {}",
                        digest.as_str()
                    ),
                ));
                continue;
            }
        }

        let findings = match cache.get(digest.as_str()) {
            Some(cached) => cached.clone(),
            None => {
                let out = crate::scan::scan_skill(&dir);
                let mut f = findings_of(&out);
                f.sort();
                cache.insert(digest.as_str().to_owned(), f.clone());
                f
            }
        };

        records.push(ScanRecord {
            source_id: e.source_id.clone(),
            layer: e.layer.clone(),
            stratum: e.stratum.clone(),
            status: "scanned".to_owned(),
            content_digest: Some(digest.as_str().to_owned()),
            reason: None,
            findings,
        });
    }

    records.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    records
}

fn findings_of(out: &crate::scan::ScanOutcome) -> Vec<CorpusFinding> {
    out.findings
        .iter()
        .map(|f| CorpusFinding {
            rule: f.rule.as_str().to_owned(),
            severity: f.severity.as_str().to_owned(),
            file: f.file.clone(),
            line: f.primary_line(),
            capability: f.capability.clone().unwrap_or_default(),
        })
        .collect()
}

/// Write records as JSONL. No timestamp, caller-visible or otherwise.
pub fn write_records(path: &Path, records: &[ScanRecord]) -> Result<(), String> {
    let mut body = String::new();
    for r in records {
        let line = serde_json::to_string(r).map_err(|e| format!("serialise record: {e}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, body).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

pub fn read_records(path: &Path) -> Result<Vec<ScanRecord>, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read findings {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(t).map_err(|e| {
                format!("{}:{}: invalid finding record: {e}", path.display(), i + 1)
            })?,
        );
    }
    Ok(out)
}

// ── statistics ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulePrevalence {
    pub rule: String,
    pub hits: usize,
    pub n: usize,
}

impl RulePrevalence {
    /// Hits per skill. `0.0` when the stratum is empty, never `NaN`.
    pub fn prevalence(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.hits as f64 / self.n as f64
        }
    }
}

/// One `dimension=value` cell: its denominator and its per-rule prevalence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    pub dimension: String,
    pub value: String,
    pub n: usize,
    pub failed: usize,
    pub rules: Vec<RulePrevalence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusStats {
    pub total_entries: usize,
    pub scanned: usize,
    pub failed: usize,
    /// Failure reason -> count. Ordered, so the report does not churn.
    pub failure_reasons: BTreeMap<String, usize>,
    pub overall: Vec<RulePrevalence>,
    pub groups: Vec<GroupStats>,
}

/// Which dimensions to stratify on, beyond `layer`.
pub const DEFAULT_DIMENSIONS: &[&str] = &["layer", "size", "scripts", "declared", "license"];

/// Compute stratified prevalence.
///
/// Prevalence(R) = |{skill with >=1 finding for R}| / |scanned skills in group|.
/// Failed entries are excluded from `n` and reported separately: including them
/// in the denominator would understate prevalence, dropping them would hide the
/// gap.
pub fn stats(records: &[ScanRecord], dimensions: &[&str]) -> CorpusStats {
    let scanned: Vec<&ScanRecord> = records.iter().filter(|r| r.is_scanned()).collect();
    let failed = records.len() - scanned.len();

    let mut failure_reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in records.iter().filter(|r| !r.is_scanned()) {
        let reason = r
            .reason
            .clone()
            .unwrap_or_else(|| "unknown".to_owned())
            .split(':')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_owned();
        *failure_reasons.entry(reason).or_insert(0) += 1;
    }

    let overall = prevalence_for(&scanned);

    // `layer` is its own field; the rest live in the stratum map.
    type Selector = Box<dyn Fn(&ScanRecord) -> Option<String>>;
    let mut group_specs: Vec<(String, Selector)> = Vec::new();
    for d in dimensions {
        if *d == "layer" {
            group_specs.push(("layer".to_owned(), Box::new(|r| Some(r.layer.clone()))));
        } else {
            let key = (*d).to_owned();
            group_specs.push((
                key.clone(),
                Box::new(move |r: &ScanRecord| r.stratum.get(&key).cloned()),
            ));
        }
    }

    let mut groups: Vec<GroupStats> = Vec::new();
    for (dimension, selector) in &group_specs {
        let mut values: Vec<String> = Vec::new();
        for r in &scanned {
            if let Some(v) = selector(r) {
                if !values.contains(&v) {
                    values.push(v);
                }
            }
        }
        values.sort();
        for value in values {
            let members: Vec<&ScanRecord> = scanned
                .iter()
                .copied()
                .filter(|r| selector(r).as_deref() == Some(value.as_str()))
                .collect();
            let n = members.len();
            let failed_here = records
                .iter()
                .filter(|r| !r.is_scanned() && selector(r).as_deref() == Some(value.as_str()))
                .count();
            groups.push(GroupStats {
                dimension: dimension.clone(),
                value,
                n,
                failed: failed_here,
                rules: prevalence_for(&members),
            });
        }
    }

    CorpusStats {
        total_entries: records.len(),
        scanned: scanned.len(),
        failed,
        failure_reasons,
        overall,
        groups,
    }
}

fn prevalence_for(members: &[&ScanRecord]) -> Vec<RulePrevalence> {
    // Rule -> number of skills with at least one finding for that rule.
    let mut hits: BTreeMap<&str, usize> = BTreeMap::new();
    let mut severities: BTreeMap<&str, Severity> = BTreeMap::new();
    for r in members {
        let mut seen: Vec<&str> = Vec::new();
        for f in &r.findings {
            if !seen.contains(&f.rule.as_str()) {
                seen.push(&f.rule);
                *hits.entry(f.rule.as_str()).or_insert(0) += 1;
            }
            if let Some(sev) = Severity::parse(&f.severity) {
                let slot = severities.entry(f.rule.as_str()).or_insert(Severity::Info);
                if sev > *slot {
                    *slot = sev;
                }
            }
        }
    }
    let n = members.len();
    let mut out: Vec<RulePrevalence> = hits
        .into_iter()
        .map(|(rule, hits)| RulePrevalence {
            rule: rule.to_owned(),
            hits,
            n,
        })
        .collect();
    out.sort_by(|a, b| {
        b.prevalence()
            .partial_cmp(&a.prevalence())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.rule.cmp(&b.rule))
    });
    out
}

// ── report ────────────────────────────────────────────────────────────────

/// The honest declarations from `docs/PHASE0_CORPUS_STUDY.md` §5.1. They are
/// emitted by the generator, not typed by a human into a template, so a report
/// cannot be produced without them.
pub const HONEST_DECLARATIONS: &[&str] = &[
    "Detection is not judgement. This study does not classify any skill as malicious; it reports reproducible rule matches.",
    "Rules miss things. The miss rate for semantic prompt injection is unknown and necessarily non-zero.",
    "False positives exist. Every prevalence figure is bounded by the precision in the GOLD set; the interval for true prevalence is [P x point estimate, point estimate].",
    "The corpus is biased. GitHub code search is limited by the platform's index and every registry has its own preference; the conclusions do not necessarily generalise to private or enterprise skills.",
    "The corpus drifts. Every conclusion is bound to the collection window and the pinned commits and cannot be cited forever.",
];

/// Render a Markdown report.
pub fn report_markdown(stats: &CorpusStats, rule_set_version: &str) -> String {
    let mut o = String::new();
    o.push_str("# SkillGuard Phase 0 corpus report\n\n");
    o.push_str(&format!("Rule set version: `{rule_set_version}`.\n\n"));
    o.push_str(
        "This file is generated by `skillguard corpus report`. It is a template \
         until it is filled with a real corpus: do not cite the numbers below \
         without checking the manifest they came from.\n\n",
    );

    o.push_str("## Honest declarations\n\n");
    for d in HONEST_DECLARATIONS {
        o.push_str(&format!("- {d}\n"));
    }
    o.push('\n');

    o.push_str("## Denominators\n\n");
    o.push_str("| | count |\n|---|---|\n");
    o.push_str(&format!("| manifest entries | {} |\n", stats.total_entries));
    o.push_str(&format!("| scanned | {} |\n", stats.scanned));
    o.push_str(&format!("| failed | {} |\n", stats.failed));
    if !stats.failure_reasons.is_empty() {
        o.push('\n');
        o.push_str("Failure reasons (never folded into the denominator):\n\n");
        o.push_str("| reason | count |\n|---|---|\n");
        for (reason, count) in &stats.failure_reasons {
            o.push_str(&format!("| {} | {count} |\n", escape_cell(reason)));
        }
    }
    o.push('\n');

    o.push_str("## Overall prevalence\n\n");
    o.push_str("Prevalence(R) = skills with at least one finding for R / scanned skills.\n\n");
    o.push_str("| rule | hits | n | prevalence |\n|---|---|---|---|\n");
    for r in &stats.overall {
        o.push_str(&format!(
            "| `{}` | {} | {} | {:.1}% |\n",
            r.rule,
            r.hits,
            r.n,
            r.prevalence() * 100.0
        ));
    }
    if stats.overall.is_empty() {
        o.push_str("| _none_ | 0 | 0 | - |\n");
    }
    o.push('\n');

    o.push_str("## Stratified prevalence\n\n");
    o.push_str(
        "Every headline figure must be reported per stratum (protocol §4.2); \
         without stratification the result is dominated by one category.\n\n",
    );
    let mut current_dim = "";
    for g in &stats.groups {
        if g.dimension != current_dim {
            current_dim = &g.dimension;
            o.push_str(&format!("### by `{}`\n\n", g.dimension));
            o.push_str("| value | n | failed | top rules |\n|---|---|---|---|\n");
        }
        let top: Vec<String> = g
            .rules
            .iter()
            .take(5)
            .map(|r| format!("`{}` {:.1}%", r.rule, r.prevalence() * 100.0))
            .collect();
        o.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            escape_cell(&g.value),
            g.n,
            g.failed,
            if top.is_empty() {
                "-".to_owned()
            } else {
                top.join(", ")
            }
        ));
    }
    o.push('\n');

    o.push_str("## Limitations\n\n");
    o.push_str(
        "- Static analysis cannot see semantic prompt injection; the miss rate is unknown.\n\
         - A clean scan is not a clean skill. Read the evidence.\n\
         - Registry sources whose operators have not cleared collection are absent from this \
           report, and that absence is stated rather than worked around (protocol §3, R-4).\n",
    );
    o
}

fn escape_cell(s: &str) -> String {
    crate::text::truncate_chars(s, 60).replace('|', "\\|")
}

// ── reproduce ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ReproduceReport {
    pub checked: usize,
    pub matched: usize,
    pub missing_digest: Vec<String>,
    pub mismatched: Vec<String>,
}

impl ReproduceReport {
    pub fn ok(&self) -> bool {
        self.missing_digest.is_empty() && self.mismatched.is_empty()
    }
}

/// Recompute every manifest digest from the tree and compare.
///
/// This is the cheapest possible check of the corpus's central claim: that the
/// bytes behind each figure can still be produced.
pub fn reproduce(entries: &[ManifestEntry], tree: &Path) -> ReproduceReport {
    let mut report = ReproduceReport {
        checked: 0,
        matched: 0,
        missing_digest: Vec::new(),
        mismatched: Vec::new(),
    };
    for e in entries {
        let Some(want) = &e.content_digest else {
            report.missing_digest.push(e.source_id.clone());
            continue;
        };
        report.checked += 1;
        let dir = tree.join(&e.path);
        match crate::hash::digest_dir(&dir) {
            Ok((d, _)) if d.as_str() == want => report.matched += 1,
            Ok((d, _)) => report.mismatched.push(format!(
                "{}: manifest {want}, tree {}",
                e.source_id,
                d.as_str()
            )),
            Err(reason) => report.mismatched.push(format!("{}: {reason}", e.source_id)),
        }
    }
    report
}

// ── index a local tree into a manifest ───────────────────────────────────

/// The offline half of `fetch`: turn a directory of skills into a manifest.
///
/// Network collection is blocked on operator permission (issue #5), but this
/// step is the same for every source and is fully testable offline. It computes
/// the digest, records the git commit when the tree is a repository, and buckets
/// each skill into its strata.
pub fn index_tree(
    source: &Path,
    tree: &Path,
    layer: &str,
    source_prefix: &str,
) -> Result<Vec<ManifestEntry>, String> {
    let mut dirs = crate::walk::discover_skill_dirs(source);
    dirs.sort();
    let mut out = Vec::new();
    for dir in dirs {
        let (digest, files) = crate::hash::digest_dir(&dir)?;
        let out_scan = crate::scan::scan_skill(&dir);
        let collected = crate::hash::collect(&dir, out_scan.license_declared.as_deref())?;
        let total: u64 = files.iter().map(|f| f.size).sum();
        let rel = dir
            .strip_prefix(tree)
            .unwrap_or(&dir)
            .to_string_lossy()
            .replace('\\', "/");
        let source_id = match (
            &collected.provenance.repository,
            &collected.provenance.commit,
        ) {
            (Some(repo), Some(commit)) => format!("github:{repo}@{commit}/{rel}"),
            _ => format!("{source_prefix}:{rel}"),
        };
        let mut stratum = BTreeMap::new();
        stratum.insert("size".to_owned(), size_bucket(total).to_owned());
        stratum.insert("scripts".to_owned(), scripts_kind(&files).to_owned());
        stratum.insert(
            "declared".to_owned(),
            if out_scan.declared.declared {
                "present"
            } else {
                "none"
            }
            .to_owned(),
        );
        stratum.insert(
            "license".to_owned(),
            if out_scan.license_file_found || out_scan.license_declared.is_some() {
                "present"
            } else {
                "absent"
            }
            .to_owned(),
        );
        out.push(ManifestEntry {
            source_id,
            layer: layer.to_owned(),
            commit: collected.provenance.commit.clone(),
            content_digest: Some(digest.as_str().to_owned()),
            path: rel,
            stratum,
        });
    }
    out.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    Ok(out)
}

fn size_bucket(bytes: u64) -> &'static str {
    const KB: u64 = 1024;
    if bytes < 8 * KB {
        "lt_8k"
    } else if bytes < 32 * KB {
        "8k_32k"
    } else if bytes < 128 * KB {
        "32k_128k"
    } else {
        "gt_128k"
    }
}

fn scripts_kind(files: &[crate::hash::FileDigest]) -> &'static str {
    let mut shell = false;
    let mut python = false;
    let mut js = false;
    let mut other = false;
    for f in files {
        let ext = f.path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "sh" | "bash" | "zsh" | "fish" | "ksh" | "ps1" | "bat" | "cmd" => shell = true,
            "py" | "rb" | "pl" | "php" => python = true,
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => js = true,
            "go" | "rs" | "lua" | "awk" => other = true,
            _ => {}
        }
    }
    if shell {
        "shell"
    } else if python {
        "python"
    } else if js {
        "js"
    } else if other {
        "other"
    } else {
        "none"
    }
}

/// A manifest entry path, resolved to an absolute path.
pub fn resolve(tree: &Path, entry: &ManifestEntry) -> PathBuf {
    tree.join(&entry.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, layer: &str, rules: &[&str]) -> ScanRecord {
        ScanRecord {
            source_id: id.to_owned(),
            layer: layer.to_owned(),
            stratum: BTreeMap::new(),
            status: "scanned".to_owned(),
            content_digest: Some("sha256:x".to_owned()),
            reason: None,
            findings: rules
                .iter()
                .map(|r| CorpusFinding {
                    rule: (*r).to_owned(),
                    severity: "HIGH".to_owned(),
                    file: "SKILL.md".to_owned(),
                    line: 1,
                    capability: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn prevalence_counts_skills_not_findings() {
        // A skill with five findings for one rule still counts once in the
        // numerator: the unit of study is the skill.
        let r = ScanRecord {
            findings: vec![
                CorpusFinding {
                    rule: "R".into(),
                    severity: "HIGH".into(),
                    file: "a".into(),
                    line: 1,
                    capability: String::new(),
                },
                CorpusFinding {
                    rule: "R".into(),
                    severity: "HIGH".into(),
                    file: "b".into(),
                    line: 2,
                    capability: String::new(),
                },
            ],
            ..record("s", "L3", &[])
        };
        let s = stats(&[r], &[]);
        let p = s.overall.iter().find(|p| p.rule == "R").expect("rule R");
        assert_eq!(p.hits, 1);
        assert_eq!(p.n, 1);
        assert!((p.prevalence() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn failed_entries_are_excluded_from_n_and_reported() {
        let mut failed = record("bad", "L3", &[]);
        failed.status = "failed".to_owned();
        failed.reason = Some("no SKILL.md under /x".to_owned());
        let s = stats(&[record("a", "L3", &["R"]), failed], &[]);
        assert_eq!(s.total_entries, 2);
        assert_eq!(s.scanned, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.overall.iter().find(|p| p.rule == "R").expect("R").n, 1);
        assert!(s.failure_reasons.values().sum::<usize>() == 1);
    }

    #[test]
    fn prevalence_of_an_empty_group_is_zero_not_nan() {
        let s = stats(&[], &[]);
        assert_eq!(s.scanned, 0);
        assert!(s.overall.is_empty());
    }

    #[test]
    fn stratification_reports_each_group_with_its_own_n() {
        let mut a = record("a", "L1", &["R"]);
        a.stratum.insert("size".to_owned(), "lt_8k".to_owned());
        let mut b = record("b", "L3", &[]);
        b.stratum.insert("size".to_owned(), "gt_128k".to_owned());
        let s = stats(&[a, b], &["layer", "size"]);
        let l1 = s
            .groups
            .iter()
            .find(|g| g.dimension == "layer" && g.value == "L1")
            .expect("L1 group");
        assert_eq!(l1.n, 1);
        let big = s
            .groups
            .iter()
            .find(|g| g.dimension == "size" && g.value == "gt_128k")
            .expect("big group");
        assert_eq!(big.n, 1);
        assert!(big.rules.is_empty());
    }

    #[test]
    fn the_report_carries_the_honest_declarations() {
        let s = stats(&[record("a", "L1", &["R"])], &["layer"]);
        let md = report_markdown(&s, "0.1.0");
        for d in HONEST_DECLARATIONS {
            assert!(md.contains(d), "missing declaration: {d}");
        }
        assert!(md.contains("Denominators"));
        assert!(md.contains("| scanned | 1 |"));
    }

    #[test]
    fn size_buckets_are_monotonic() {
        assert_eq!(size_bucket(0), "lt_8k");
        assert_eq!(size_bucket(8 * 1024), "8k_32k");
        assert_eq!(size_bucket(32 * 1024), "32k_128k");
        assert_eq!(size_bucket(128 * 1024), "gt_128k");
    }
}
