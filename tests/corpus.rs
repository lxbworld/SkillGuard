//! End-to-end tests for the Phase 0 corpus pipeline (issue #1).
//!
//! The pipeline's value is reproducibility, so the tests are about determinism
//! and honest denominators rather than about specific findings: scanning twice
//! must be byte-identical, a cache must not change the result, a bad entry must
//! be recorded rather than dropped, and every figure must carry its `n`.

use skillguard::corpus::{
    self, load_cache, read_manifest, read_records, scan_manifest, stats, write_manifest,
    write_records, ManifestEntry,
};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus")
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sg-corpus-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

fn indexed() -> Vec<ManifestEntry> {
    let tree = fixtures();
    corpus::index_tree(&tree, &tree, "L3", "local").expect("index")
}

#[test]
fn indexing_produces_one_pinned_entry_per_skill() {
    let entries = indexed();
    assert_eq!(entries.len(), 3, "{entries:#?}");
    for e in &entries {
        assert!(
            e.content_digest
                .as_deref()
                .unwrap_or("")
                .starts_with("sha256:"),
            "every entry must be content-addressed: {e:?}"
        );
        assert_eq!(e.layer, "L3");
        for dim in ["size", "scripts", "declared", "license"] {
            assert!(
                e.stratum.contains_key(dim),
                "missing stratum `{dim}`: {e:?}"
            );
        }
    }
    // The index is deterministic, so re-indexing is a no-op diff.
    assert_eq!(entries, indexed());
}

#[test]
fn scanning_twice_is_byte_identical() {
    let entries = indexed();
    let tree = fixtures();

    let mut cache_a = corpus::FindingCache::new();
    let rec_a = scan_manifest(&entries, &tree, &mut cache_a);
    let out_a = tmpdir("det-a").join("f.jsonl");
    write_records(&out_a, &rec_a).expect("write a");

    let mut cache_b = corpus::FindingCache::new();
    let rec_b = scan_manifest(&entries, &tree, &mut cache_b);
    let out_b = tmpdir("det-b").join("f.jsonl");
    write_records(&out_b, &rec_b).expect("write b");

    let a = std::fs::read(&out_a).expect("read a");
    let b = std::fs::read(&out_b).expect("read b");
    assert_eq!(a, b, "the same manifest must scan to the same bytes");
    assert!(
        !String::from_utf8_lossy(&a).contains("observed_at"),
        "the dataset must carry no timestamp"
    );
}

#[test]
fn a_warm_cache_returns_the_same_result() {
    let entries = indexed();
    let tree = fixtures();
    let cache_path = tmpdir("cache").join("cache.json");

    let mut cold = corpus::FindingCache::new();
    let cold_records = scan_manifest(&entries, &tree, &mut cold);
    corpus::save_cache(&cache_path, &cold).expect("save cache");

    let mut warm = load_cache(&cache_path).expect("load cache");
    assert_eq!(warm.len(), 3, "one cache entry per unique content digest");
    let warm_records = scan_manifest(&entries, &tree, &mut warm);
    assert_eq!(cold_records, warm_records);
}

#[test]
fn a_moving_ref_is_refused_not_scanned() {
    let mut entries = indexed();
    entries[0].commit = Some("main".to_owned());
    let records = scan_manifest(&entries, &fixtures(), &mut corpus::FindingCache::new());
    let bad = records
        .iter()
        .find(|r| r.source_id == entries[0].source_id)
        .expect("record");
    assert!(!bad.is_scanned(), "a branch name must be refused");
    assert!(bad.reason.as_deref().unwrap_or("").contains("40-hex"));
}

#[test]
fn a_digest_mismatch_is_a_failure_not_a_silent_rescan() {
    let mut entries = indexed();
    entries[0].content_digest = Some("sha256:".to_owned() + &"0".repeat(64));
    let records = scan_manifest(&entries, &fixtures(), &mut corpus::FindingCache::new());
    let bad = records
        .iter()
        .find(|r| r.source_id == entries[0].source_id)
        .expect("record");
    assert!(!bad.is_scanned());
    assert!(bad
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("content digest mismatch"));
}

#[test]
fn failed_entries_appear_in_the_denominators_and_are_not_counted_as_clean() {
    let entries = indexed();
    let mut records = scan_manifest(&entries, &fixtures(), &mut corpus::FindingCache::new());
    // Add a failure by hand, as a batch would after a missing tree.
    let mut broken = entries[0].clone();
    broken.source_id = "local:missing".to_owned();
    broken.path = "does-not-exist".to_owned();
    records.extend(scan_manifest(
        &[broken],
        &fixtures(),
        &mut corpus::FindingCache::new(),
    ));

    let s = stats(&records, corpus::DEFAULT_DIMENSIONS);
    assert_eq!(s.total_entries, 4);
    assert_eq!(s.scanned, 3);
    assert_eq!(s.failed, 1);
    assert!(
        s.failure_reasons.values().sum::<usize>() == 1,
        "the failure must be attributed: {:#?}",
        s.failure_reasons
    );
    let md = corpus::report_markdown(&s, "0.1.0");
    assert!(md.contains("| failed | 1 |"), "{md}");
    for d in corpus::HONEST_DECLARATIONS {
        assert!(md.contains(d));
    }
}

#[test]
fn reproduce_detects_content_drift() {
    // Copy the fixture corpus so the test can mutate it.
    let dir = tmpdir("reproduce");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir");
    copy_dir(&fixtures(), &tree);

    let entries = corpus::index_tree(&tree, &tree, "L3", "local").expect("index");

    let ok = corpus::reproduce(&entries, &tree);
    assert!(ok.ok(), "a fresh copy must reproduce: {ok:?}");
    assert_eq!(ok.matched, 3);

    // One byte in one skill.
    let target = tree.join(&entries[0].path).join("SKILL.md");
    let mut body = std::fs::read_to_string(&target).expect("read");
    body.push('\n');
    std::fs::write(&target, body).expect("write");

    let drift = corpus::reproduce(&entries, &tree);
    assert!(!drift.ok());
    assert_eq!(drift.mismatched.len(), 1, "{drift:?}");
}

#[test]
fn a_manifest_round_trips_through_jsonl() {
    let entries = indexed();
    let path = tmpdir("manifest").join("corpus.jsonl");
    write_manifest(&path, &entries).expect("write");
    let back = read_manifest(&path).expect("read");
    assert_eq!(entries, back);
}

#[test]
fn the_pipeline_can_be_scrubbed_of_evidence() {
    // R-2: the published dataset must not contain payloads. The record type has
    // no evidence field at all, so this is a structural guarantee; assert it so
    // a future field addition has to think about it.
    let entries = indexed();
    let records = scan_manifest(&entries, &fixtures(), &mut corpus::FindingCache::new());
    let out = tmpdir("redacted").join("f.jsonl");
    write_records(&out, &records).expect("write");
    let body = std::fs::read_to_string(&out).expect("read");
    assert!(
        !body.contains("get.example.net/install"),
        "the injected network payload must not be in the dataset"
    );
    assert!(body.contains("DL_PIPE_TO_SHELL"), "{body}");
    // And reading it back yields the same records.
    assert_eq!(read_records(&out).expect("read back"), records);
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in walkdir_lite(from) {
        let rel = entry.strip_prefix(from).expect("relative");
        let dest = to.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest).expect("mkdir");
        } else {
            if let Some(p) = dest.parent() {
                std::fs::create_dir_all(p).expect("mkdir");
            }
            std::fs::copy(&entry, &dest).expect("copy");
        }
    }
}

fn walkdir_lite(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out.sort();
    out
}
