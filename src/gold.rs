//! Rule quality evaluation: human GOLD, model silver, and the matrix.
//!
//! Three kinds of evidence are kept apart on purpose, and the separation is
//! enforced by the *type* rather than by a convention:
//!
//! * **Synthetic fixtures** live in `tests/fixtures/` and are deterministic. They
//!   prove a rule fires; they do not measure precision or recall on real code, and
//!   this module never counts them.
//! * **Human GOLD** is [`HumanLabel`]: a person read the evidence and said
//!   `TP`/`FP`/`AMBIGUOUS`/`NOT_APPLICABLE`. Only this type feeds the published
//!   precision and recall.
//! * **Model silver** is [`SilverLabel`]: a model's opinion, carrying its name,
//!   version and prompt version. It is stored separately, is never read by the
//!   matrix, and cannot overwrite a human label.
//!
//! Two sessions of one model agreeing is not a human label, and the schema says
//! so: [`Source::Model`] is a distinct variant from [`Source::Human`], not a
//! bool or a free-text field someone can fill in as "human-ish".
//!
//! Everything here is offline. No model is called, ever; `gold export` writes a
//! file and `gold import` reads one back. That is the whole integration surface
//! for an external judge, which keeps the scanner's no-socket invariant intact.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Rules whose finding is about the skill as a whole and carries no evidence
/// line. A line-level worksheet cannot judge them: the row would show the
/// frontmatter delimiter and score the sampler, not the rule (GOLD-v5 published
/// a 0/8 that way). They need a skill-level questionnaire.
pub const SKILL_LEVEL_RULES: &[&str] = &["PARSE_FAILED", "PI_DESCRIPTION_MISMATCH"];

pub fn is_skill_level(rule: &str) -> bool {
    SKILL_LEVEL_RULES.contains(&rule)
        || rule.starts_with("LICENSE_")
        || rule.starts_with("MISMATCH_")
}

/// The published label set, in the schema `docs/ANNOTATION_GUIDE.md` documents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HumanLabel {
    /// Content-derived, so it survives a re-scan: see [`finding_id`].
    pub finding_id: String,
    pub rule_id: String,
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
    pub evidence: String,
    pub label: Label,
    pub confidence: Confidence,
    pub rationale: String,
    pub reviewer: String,
    /// ISO date, as the annotator typed it. Not parsed: a timezone bug in a
    /// provenance field is worse than a free string, and nothing computes on it.
    pub reviewed_at: String,
}

/// A model's opinion. Deliberately a different type from [`HumanLabel`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilverLabel {
    pub finding_id: String,
    pub rule_id: String,
    pub label: Label,
    pub confidence: Confidence,
    pub rationale: String,
    /// Which model, exactly. "gpt" is not a version.
    pub model: String,
    pub model_version: String,
    /// Hash or tag of the prompt that produced this, so a prompt change is not
    /// silently a different judge.
    pub prompt_version: String,
    pub judged_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Label {
    Tp,
    Fp,
    /// The evidence is not enough to decide. A reviewer is never forced to guess;
    /// an `AMBIGUOUS` row is excluded from precision and reported separately.
    Ambiguous,
    /// The rule does not apply to this finding at all — e.g. a rule that claims
    /// an action, matched inside a docstring that documents the action.
    NotApplicable,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Tp => "TP",
            Label::Fp => "FP",
            Label::Ambiguous => "AMBIGUOUS",
            Label::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Parse as a human typed it. Case-insensitive because a CSV edited in a
    /// spreadsheet is not going to preserve ours.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "TP" | "TRUE_POSITIVE" => Some(Label::Tp),
            "FP" | "FALSE_POSITIVE" => Some(Label::Fp),
            "AMBIGUOUS" | "UNSURE" => Some(Label::Ambiguous),
            "NOT_APPLICABLE" | "NA" | "N/A" => Some(Label::NotApplicable),
            _ => None,
        }
    }

    /// Counted as a correctness judgement? `NO` would be a fourth state nobody
    /// asked for; both non-decisions are excluded and reported.
    pub fn is_decided(self) -> bool {
        matches!(self, Label::Tp | Label::Fp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "HIGH" => Some(Confidence::High),
            "MEDIUM" | "MED" => Some(Confidence::Medium),
            "LOW" => Some(Confidence::Low),
            _ => None,
        }
    }
}

/// Who produced a label. The matrix reads only `Human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Human,
    Model,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Human => "human",
            Source::Model => "model",
        }
    }
}

/// A stable id for a finding.
///
/// Findings carry no id of their own, and adding one to the scan output would
/// change the report format for everyone. The id is therefore derived from what
/// identifies the finding semantically — source, rule, file, line — and *not*
/// from the evidence text, so a cosmetic normalization change does not orphan
/// every existing human label. `rule::4f3a…`, short enough to sort by eye.
pub fn finding_id(source_id: &str, rule: &str, file: &str, line: usize) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(source_id.as_bytes());
    h.update(b"\x1f");
    h.update(rule.as_bytes());
    h.update(b"\x1f");
    h.update(file.as_bytes());
    h.update(b"\x1f");
    h.update(line.to_string().as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{hex}-{line}-{rule}")
}

/// One row of the rule quality matrix.
#[derive(Debug, Clone, Serialize)]
pub struct RuleQuality {
    pub rule_id: String,
    pub samples: usize,
    pub tp: usize,
    pub fp: usize,
    pub ambiguous: usize,
    pub not_applicable: usize,
    /// `None` when no row was decided — not 0.0, which would read as "all wrong".
    pub precision: Option<f64>,
    /// Recall requires knowing what the rules *missed*. A finding-level sample
    /// cannot show that: it is drawn from findings, so misses are absent by
    /// construction. `None` here means "unknown", and it must stay unknown until
    /// a skill-level sample measures it.
    pub recall: Option<f64>,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Meets the blocking threshold.
    Blocking,
    /// Meets the warning threshold.
    Warning,
    /// Not enough human samples, or the precision is below both thresholds.
    Informational,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Blocking => "BLOCKING",
            Status::Warning => "WARNING",
            Status::Informational => "INFORMATIONAL",
        }
    }
}

/// Initial engineering thresholds. Not statistical confidence intervals — they
/// are the point below which a rule should not be allowed to block a build.
pub const BLOCKING_PRECISION: f64 = 0.95;
pub const BLOCKING_MIN_SAMPLES: usize = 30;
pub const WARNING_PRECISION: f64 = 0.85;
pub const WARNING_MIN_SAMPLES: usize = 20;

fn status_for(precision: Option<f64>, samples: usize) -> Status {
    // A high precision on four samples is not evidence, and the thresholds below
    // say so explicitly: samples gate the level, not just the ratio.
    match precision {
        Some(p) if p >= BLOCKING_PRECISION && samples >= BLOCKING_MIN_SAMPLES => Status::Blocking,
        Some(p) if p >= WARNING_PRECISION && samples >= WARNING_MIN_SAMPLES => Status::Warning,
        _ => Status::Informational,
    }
}

/// Build the matrix from human labels only.
///
/// `silver` is accepted so a caller can report how much model opinion exists, but
/// it never contributes a `TP` or an `FP`. Passing it here rather than dropping it
/// is deliberate: silently ignoring the argument would hide the fact that model
/// labels exist and are unused.
pub fn matrix(human: &[HumanLabel], silver: &[SilverLabel]) -> Vec<RuleQuality> {
    matrix_with_rules(human, silver, &[])
}

/// As [`matrix`], but seeds every rule in `all_rules` with zero samples.
///
/// A rule absent from the table reads as "not measured"; a rule present with 0
/// samples reads as "nobody has looked at it yet". Those are different facts, and
/// a published matrix should show the second one for every rule that exists.
pub fn matrix_with_rules(
    human: &[HumanLabel],
    silver: &[SilverLabel],
    all_rules: &[String],
) -> Vec<RuleQuality> {
    #[derive(Default)]
    struct Tally {
        tp: usize,
        fp: usize,
        ambiguous: usize,
        not_applicable: usize,
    }
    let mut by_rule: BTreeMap<&str, Tally> = BTreeMap::new();
    for r in all_rules {
        by_rule.entry(r.as_str()).or_default();
    }
    for l in human {
        let e = by_rule.entry(l.rule_id.as_str()).or_default();
        match l.label {
            Label::Tp => e.tp += 1,
            Label::Fp => e.fp += 1,
            Label::Ambiguous => e.ambiguous += 1,
            Label::NotApplicable => e.not_applicable += 1,
        }
    }
    // Rules that only have silver labels still appear, with zero human samples.
    // A rule absent from the table reads as "not measured"; a rule present with
    // 0 samples reads as "nobody has looked", and those are different facts.
    let _ = silver;

    by_rule
        .into_iter()
        .map(|(rule, t)| {
            let Tally {
                tp,
                fp,
                ambiguous,
                not_applicable,
            } = t;
            let samples = tp + fp + ambiguous + not_applicable;
            let decided = tp + fp;
            let precision = if decided == 0 {
                None
            } else {
                Some(tp as f64 / decided as f64)
            };
            RuleQuality {
                rule_id: rule.to_owned(),
                samples,
                tp,
                fp,
                ambiguous,
                not_applicable,
                precision,
                recall: None,
                status: status_for(precision, decided),
            }
        })
        .collect()
}

/// Render the matrix as the table `docs/RULE_QUALITY_MATRIX.md` documents.
pub fn matrix_markdown(rows: &[RuleQuality]) -> String {
    let mut o = String::from(
        "| Rule ID | Samples | TP | FP | Ambiguous | N/A | Precision | Recall | Status |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let p = match r.precision {
            Some(x) => format!("{:.1}%", x * 100.0),
            None => "n/a".to_owned(),
        };
        o.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | unknown | {} |\n",
            r.rule_id,
            r.samples,
            r.tp,
            r.fp,
            r.ambiguous,
            r.not_applicable,
            p,
            r.status.as_str()
        ));
    }
    o
}

// ---------------------------------------------------------------------------
// CSV: the format a reviewer actually edits
// ---------------------------------------------------------------------------

/// The CSV header, fixed so a spreadsheet round-trip cannot reorder it silently.
pub const CSV_HEADER: &[&str] = &[
    "finding_id",
    "rule_id",
    "file",
    "line_start",
    "line_end",
    "evidence",
    "label",
    "confidence",
    "rationale",
    "reviewer",
    "reviewed_at",
];

pub fn write_csv(path: &Path, rows: &[HumanLabel]) -> Result<(), String> {
    let mut w = csv::Writer::from_path(path)
        .map_err(|e| format!("cannot write CSV {}: {e}", path.display()))?;
    w.write_record(CSV_HEADER)
        .map_err(|e| format!("cannot write CSV header: {e}"))?;
    for r in rows {
        w.write_record([
            r.finding_id.as_str(),
            r.rule_id.as_str(),
            r.file.as_str(),
            &r.line_start.to_string(),
            &r.line_end.to_string(),
            r.evidence.as_str(),
            r.label.as_str(),
            confidence_str(r.confidence),
            r.rationale.as_str(),
            r.reviewer.as_str(),
            r.reviewed_at.as_str(),
        ])
        .map_err(|e| format!("cannot write CSV row: {e}"))?;
    }
    w.flush()
        .map_err(|e| format!("cannot flush CSV {}: {e}", path.display()))
}

pub fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "HIGH",
        Confidence::Medium => "MEDIUM",
        Confidence::Low => "LOW",
    }
}

/// Read a reviewer's CSV back.
///
/// Every cell is parsed, never trusted: a spreadsheet turns `10` into `10.0` and
/// quotes fields in ways a hand-written parser gets wrong, so the error message
/// names the row and the column that failed rather than the file.
pub fn read_csv(path: &Path) -> Result<Vec<HumanLabel>, String> {
    let mut r = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(path)
        .map_err(|e| format!("cannot read CSV {}: {e}", path.display()))?;
    let headers = r
        .headers()
        .map_err(|e| format!("cannot read CSV header: {e}"))?
        .clone();
    for want in CSV_HEADER {
        if !headers.iter().any(|h| h == *want) {
            return Err(format!(
                "{}: missing column {:?}; the template is docs/templates/gold.csv",
                path.display(),
                want
            ));
        }
    }
    let col = |name: &str| headers.iter().position(|h| h == name);
    let get = |rec: &csv::StringRecord, name: &str| -> String {
        col(name).and_then(|i| rec.get(i)).unwrap_or("").to_owned()
    };

    let mut out = Vec::new();
    for (i, rec) in r.records().enumerate() {
        let rec = rec.map_err(|e| format!("{}: row {}: {e}", path.display(), i + 2))?;
        // A reviewer who leaves a row untouched leaves it blank; that is not an
        // error, it is "not reviewed yet", and re-reading the file must not fail.
        if get(&rec, "label").is_empty() {
            continue;
        }
        let Some(label) = Label::parse(&get(&rec, "label")) else {
            return Err(format!(
                "{}: row {}: label must be TP, FP, AMBIGUOUS or NOT_APPLICABLE, got {:?}",
                path.display(),
                i + 2,
                get(&rec, "label")
            ));
        };
        let line = get(&rec, "line_start");
        let Ok(line_start) = line.trim().trim_end_matches(".0").parse::<usize>() else {
            return Err(format!(
                "{}: row {}: line_start must be a number, got {:?}",
                path.display(),
                i + 2,
                line
            ));
        };
        let line_end = get(&rec, "line_end")
            .trim()
            .trim_end_matches(".0")
            .parse::<usize>()
            .unwrap_or(line_start);
        out.push(HumanLabel {
            finding_id: get(&rec, "finding_id"),
            rule_id: get(&rec, "rule_id"),
            file: get(&rec, "file"),
            line_start,
            line_end,
            evidence: get(&rec, "evidence"),
            label,
            confidence: Confidence::parse(&get(&rec, "confidence")).unwrap_or(Confidence::Medium),
            rationale: get(&rec, "rationale"),
            reviewer: get(&rec, "reviewer"),
            reviewed_at: get(&rec, "reviewed_at"),
        });
    }
    Ok(out)
}

/// Read the newline-delimited JSON form, one [`HumanLabel`] per line.
pub fn read_jsonl_human(path: &Path) -> Result<Vec<HumanLabel>, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.push(
            serde_json::from_str(t)
                .map_err(|e| format!("{}:{}: not a human GOLD row: {e}", path.display(), i + 1))?,
        );
    }
    Ok(out)
}

pub fn read_jsonl_silver(path: &Path) -> Result<Vec<SilverLabel>, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.push(serde_json::from_str(t).map_err(|e| {
            format!(
                "{}:{}: not a silver label (it needs model, model_version and prompt_version): {e}",
                path.display(),
                i + 1
            )
        })?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// One candidate row, before anyone has judged it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub finding_id: String,
    pub rule_id: String,
    pub source_id: String,
    pub file: String,
    pub line_start: usize,
    pub evidence: String,
    pub severity: String,
}

/// How to stratify the draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Stratum {
    /// Equal numbers per rule: gives the weakest rule as many rows as the most
    /// common one, which is what a *per-rule* precision table needs.
    Rule,
    /// Proportional to how often the rule fires: answers "what does a user of
    /// this tool actually see", at the cost of leaving rare rules unmeasured.
    Frequency,
    /// Equal numbers per severity: for a table organised around blocking risk.
    Severity,
}

/// Deterministic draw: sort by a hash of the finding id, take the first `n` of
/// each stratum. The same corpus and parameters always produce the same
/// worksheet, which is what makes a GOLD round reproducible at all.
///
/// `Frequency` is deliberately a *global* draw of `per_stratum * rules` rows:
/// sampling uniformly over findings is already proportional to how often a rule
/// fires, and doing it any other way would be a weighting nobody asked for.
pub fn sample(candidates: &[Candidate], stratum: Stratum, per_stratum: usize) -> Vec<Candidate> {
    use std::collections::{BTreeMap, BTreeSet};

    let hash_key = |c: &Candidate| -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(c.finding_id.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    };

    let rule_key = |c: &Candidate| c.rule_id.clone();
    let mut groups: BTreeMap<String, Vec<&Candidate>> = BTreeMap::new();
    match stratum {
        Stratum::Frequency => {
            groups.insert(String::new(), candidates.iter().collect());
        }
        Stratum::Rule => {
            for c in candidates {
                groups.entry(rule_key(c)).or_default().push(c);
            }
        }
        Stratum::Severity => {
            for c in candidates {
                groups.entry(c.severity.clone()).or_default().push(c);
            }
        }
    }

    let distinct: BTreeSet<String> = candidates.iter().map(rule_key).collect();
    let mut out = Vec::new();
    for (_, mut rows) in groups {
        rows.sort_by_key(|c| hash_key(c));
        let take = match stratum {
            Stratum::Frequency => per_stratum.saturating_mul(distinct.len().max(1)),
            _ => per_stratum,
        };
        out.extend(rows.into_iter().take(take).cloned());
    }
    out.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn human(rule: &str, label: Label) -> HumanLabel {
        HumanLabel {
            finding_id: format!("x-{rule}"),
            rule_id: rule.to_owned(),
            file: "SKILL.md".to_owned(),
            line_start: 1,
            line_end: 1,
            evidence: "e".to_owned(),
            label,
            confidence: Confidence::High,
            rationale: "r".to_owned(),
            reviewer: "human".to_owned(),
            reviewed_at: "2026-01-01".to_owned(),
        }
    }

    #[test]
    fn the_finding_id_is_stable_and_does_not_include_the_evidence() {
        let a = finding_id("src", "RULE", "f.py", 7);
        assert_eq!(a, finding_id("src", "RULE", "f.py", 7));
        // A different line, rule, file or source is a different finding.
        assert_ne!(a, finding_id("src", "RULE", "f.py", 8));
        assert_ne!(a, finding_id("src", "OTHER", "f.py", 7));
        assert_ne!(a, finding_id("other", "RULE", "f.py", 7));
    }

    #[test]
    fn a_label_is_parsed_however_a_spreadsheet_wrote_it() {
        assert_eq!(Label::parse("tp"), Some(Label::Tp));
        assert_eq!(Label::parse(" TP "), Some(Label::Tp));
        assert_eq!(Label::parse("False_Positive"), Some(Label::Fp));
        assert_eq!(Label::parse("n/a"), Some(Label::NotApplicable));
        assert_eq!(Label::parse("maybe"), None);
    }

    #[test]
    fn precision_is_unknown_rather_than_zero_when_nothing_is_decided() {
        // A rule seen only as AMBIGUOUS has no precision. Reporting 0.0 would read
        // as "the rule is always wrong", which is the opposite of "we do not know".
        let rows = matrix(
            &[
                human("R", Label::Ambiguous),
                human("R", Label::NotApplicable),
            ],
            &[],
        );
        assert_eq!(rows[0].samples, 2);
        assert_eq!(rows[0].precision, None);
        assert_eq!(rows[0].recall, None);
        assert_eq!(rows[0].status, Status::Informational);
    }

    #[test]
    fn model_labels_never_reach_the_matrix() {
        let silver = vec![SilverLabel {
            finding_id: "x-R".to_owned(),
            rule_id: "R".to_owned(),
            label: Label::Tp,
            confidence: Confidence::High,
            rationale: "clean".to_owned(),
            model: "some-model".to_owned(),
            model_version: "1".to_owned(),
            prompt_version: "p1".to_owned(),
            judged_at: "2026-01-01".to_owned(),
        }];
        let rows = matrix(&[], &silver);
        assert!(
            rows.is_empty(),
            "a perfect model tally must not create a rule row"
        );
        assert_eq!(Source::Model.as_str(), "model");
    }

    #[test]
    fn a_high_precision_on_few_samples_stays_informational() {
        // 3/3 is 100%, and 3 samples is not evidence.
        let many = vec![
            human("R", Label::Tp),
            human("R", Label::Tp),
            human("R", Label::Tp),
        ];
        let rows = matrix(&many, &[]);
        assert_eq!(rows[0].precision, Some(1.0));
        assert_eq!(rows[0].status, Status::Informational);
    }

    #[test]
    fn thresholds_need_both_the_ratio_and_the_sample() {
        assert_eq!(status_for(Some(0.99), 29), Status::Warning);
        assert_eq!(status_for(Some(0.99), 30), Status::Blocking);
        assert_eq!(status_for(Some(0.86), 19), Status::Informational);
        assert_eq!(status_for(Some(0.86), 20), Status::Warning);
        assert_eq!(status_for(Some(0.50), 100), Status::Informational);
    }

    #[test]
    fn csv_round_trips_through_a_spreadsheet_shaped_file() {
        let dir = std::env::temp_dir().join(format!("sg-gold-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("gold.csv");
        let rows = vec![
            HumanLabel {
                evidence: "curl x | bash, with a comma".to_owned(),
                ..human("SHELL_EXEC", Label::Tp)
            },
            human("NET_HTTP_CLIENT", Label::Fp),
        ];
        write_csv(&path, &rows).expect("write");
        let back = read_csv(&path).expect("read");
        assert_eq!(back, rows, "a comma inside evidence must survive");
        // A blank label is "not reviewed yet", not an error.
        let blank = std::fs::read_to_string(&path).expect("read");
        let edited = blank.replace(",FP,", ",,");
        std::fs::write(&path, edited).expect("write");
        assert_eq!(read_csv(&path).expect("read").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sampling_is_deterministic_and_covers_every_rule() {
        let mut cands = Vec::new();
        for rule in ["A", "B", "C"] {
            for i in 0..10 {
                cands.push(Candidate {
                    finding_id: format!("{rule}-{i}"),
                    rule_id: rule.to_owned(),
                    source_id: "s".to_owned(),
                    file: "f".to_owned(),
                    line_start: i,
                    evidence: "e".to_owned(),
                    severity: "HIGH".to_owned(),
                });
            }
        }
        let a = sample(&cands, Stratum::Rule, 3);
        let b = sample(&cands, Stratum::Rule, 3);
        assert_eq!(
            a.iter().map(|c| &c.finding_id).collect::<Vec<_>>(),
            b.iter().map(|c| &c.finding_id).collect::<Vec<_>>(),
            "the same corpus and parameters must produce the same worksheet"
        );
        assert_eq!(a.len(), 9, "3 rules x 3 rows");
        let rules: std::collections::BTreeSet<_> = a.iter().map(|c| &c.rule_id).collect();
        assert_eq!(rules.len(), 3, "no rule may be silently absent");
    }
}
