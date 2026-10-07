//! Interoperability with lockfiles written by other tools.
//!
//! # Why this exists
//!
//! `skills-lock.json` (vercel-labs/skills, npm `skills`) has more than seven
//! million weekly downloads. Replacing it is not a plan; being able to read it
//! is. This module imports it so a project can adopt policy enforcement without
//! changing where its skills come from.
//!
//! # What is deliberately not claimed
//!
//! An imported digest is **not** content-verified by us. We do not know the
//! hashing algorithm that produced it, so we record it as `legacy_digest` and
//! say plainly in the output that it is unverified. Pretending otherwise would
//! be the exact failure this project exists to prevent.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ForeignEntry {
    pub name: String,
    pub source: String,
    pub commit: Option<String>,
    pub digest: Option<String>,
    pub version: Option<String>,
    /// A GitHub tree SHA (upstream format v3). Recorded but never treated as a
    /// content digest: we cannot reproduce it, so it proves nothing here.
    pub folder_hash: Option<String>,
}

/// `skills-lock.json`, as written by vercel-labs/skills.
#[derive(Debug, Deserialize)]
struct SkillsLock {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    skills: std::collections::BTreeMap<String, SkillsLockEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SkillsLockEntry {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    source_type: Option<String>,
    /// Upstream spells this `ref`.
    #[serde(default, rename = "ref")]
    ref_: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    computed_hash: Option<String>,
    #[serde(default)]
    version: Option<String>,
    /// Folder hash added in v3 of the upstream format.
    #[serde(default)]
    skill_folder_hash: Option<String>,
}

/// Read a foreign lockfile and flatten it into entries.
///
/// Unrecognised shapes produce an empty list rather than a wrong answer; the
/// caller reports the count so a silent zero cannot be mistaken for success.
pub fn read_foreign_lock(path: &Path) -> Result<Vec<ForeignEntry>, String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    if name.contains("skills-lock") {
        return read_skills_lock(&src, path);
    }
    if name == "package.json" {
        return read_package_json(&src, path);
    }
    Err(format!(
        "unrecognised lockfile {name}; expected skills-lock.json or package.json"
    ))
}

/// Upstream format versions we know how to read.
const KNOWN_SKILLS_LOCK_VERSIONS: &[u32] = &[1, 2, 3];

fn read_skills_lock(src: &str, path: &Path) -> Result<Vec<ForeignEntry>, String> {
    let lock: SkillsLock = serde_json::from_str(src)
        .map_err(|e| format!("{} is not a valid skills-lock.json: {e}", path.display()))?;

    // An unknown schema version means the field meanings may have changed. Say
    // so instead of guessing, because a silently wrong digest is worse than a
    // refused import.
    if let Some(v) = lock.version {
        if !KNOWN_SKILLS_LOCK_VERSIONS.contains(&v) {
            return Err(format!(
                "{} declares skills-lock version {v}, which this build does not know how to read \
                 (known: {KNOWN_SKILLS_LOCK_VERSIONS:?}). Refusing rather than importing digests \
                 whose meaning may have changed.",
                path.display()
            ));
        }
    }

    let mut out: Vec<ForeignEntry> = Vec::new();
    for (name, e) in lock.skills {
        let source = match (&e.source, &e.source_type) {
            (Some(s), _) => s.clone(),
            (None, Some(t)) => t.clone(),
            (None, None) => continue,
        };
        // Prefer an explicit full commit; fall back to `ref` only when it looks
        // like a SHA, because a branch name is not reproducible.
        let commit = e
            .commit
            .clone()
            .or_else(|| e.ref_.clone())
            .filter(|c| c.len() == 40 && c.chars().all(|ch| ch.is_ascii_hexdigit()));

        out.push(ForeignEntry {
            name,
            source,
            commit,
            digest: e.computed_hash.clone(),
            version: e.version.clone(),
            folder_hash: e.skill_folder_hash.clone(),
        });
    }
    Ok(out)
}

/// `package.json` with an `agent-skill` keyword: the npm-native route that
/// `skillpm` uses. Recorded for visibility; npm's own `package-lock.json`
/// remains the authority for the dependency tree.
fn read_package_json(src: &str, path: &Path) -> Result<Vec<ForeignEntry>, String> {
    let v: serde_json::Value = serde_json::from_str(src)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let is_skill = v
        .get("keywords")
        .and_then(|k| k.as_array())
        .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("agent-skill")));
    if !is_skill {
        return Ok(Vec::new());
    }
    let name = v
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("package")
        .to_owned();
    Ok(vec![ForeignEntry {
        name,
        source: format!(
            "npm:{}",
            v.get("name").and_then(|n| n.as_str()).unwrap_or("")
        ),
        commit: None,
        digest: None,
        version: v.get("version").and_then(|x| x.as_str()).map(str::to_owned),
        folder_hash: None,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sg-import-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_default();
        let p = d.join("skills-lock.json");
        std::fs::write(&p, body).unwrap_or_default();
        p
    }

    #[test]
    fn reads_a_realistic_skills_lock() {
        let p = tmp(
            "real",
            r#"{
              "version": 1,
              "skills": {
                "frontend-design": {
                  "source": "anthropics/skills",
                  "sourceType": "github",
                  "computedHash": "063a0e6448123cd359ad0044cc46b0e490cc7964d45ef4bb9fd842bd2ffbca67",
                  "path": "skills/frontend-design"
                },
                "shadcn": {
                  "source": "shadcn/ui",
                  "sourceType": "github",
                  "skillFolderHash": "5e7d2c1a"
                }
              }
            }"#,
        );
        let entries = read_foreign_lock(&p).unwrap_or_default();
        assert_eq!(entries.len(), 2);

        let fd = entries
            .iter()
            .find(|e| e.name == "frontend-design")
            .unwrap();
        assert_eq!(fd.source, "anthropics/skills");
        assert!(fd.digest.is_some(), "computedHash must be imported");
        assert!(fd.commit.is_none(), "no commit was pinned upstream");

        let shadcn = entries.iter().find(|e| e.name == "shadcn").unwrap();
        assert!(
            shadcn.digest.is_none(),
            "a GitHub tree SHA is not a content digest and must not be imported as one"
        );
    }

    #[test]
    fn accepts_only_full_commit_shas() {
        let p = tmp(
            "refs",
            r#"{"version":1,"skills":{
              "a":{"source":"o/a","ref":"main"},
              "b":{"source":"o/b","ref":"89bd10a"},
              "c":{"source":"o/c","ref":"89bd10a1f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"}
            }}"#,
        );
        let entries = read_foreign_lock(&p).unwrap_or_default();
        let by = |n: &str| {
            entries
                .iter()
                .find(|e| e.name == n)
                .and_then(|e| e.commit.clone())
        };
        assert_eq!(by("a"), None, "a branch name is not reproducible");
        assert_eq!(by("b"), None, "a short SHA is refused");
        assert!(by("c").is_some(), "a full SHA is accepted");
    }

    #[test]
    fn malformed_input_is_an_error_not_an_empty_success() {
        let p = tmp("bad", "{not json");
        assert!(read_foreign_lock(&p).is_err());
    }

    #[test]
    fn unknown_format_version_is_refused_not_guessed() {
        // Reading a schema whose meaning changed would import digests that
        // verify nothing. Refusing is the safer answer.
        let p = tmp("v99", r#"{"version":99,"skills":{"a":{"source":"o/a"}}}"#);
        let err = read_foreign_lock(&p).unwrap_err();
        assert!(err.contains("99"), "{err}");
        assert!(err.contains("Refusing"), "{err}");
    }

    #[test]
    fn known_versions_are_accepted() {
        for v in [1, 2, 3] {
            let p = tmp(
                &format!("v{v}"),
                &format!(r#"{{"version":{v},"skills":{{"a":{{"source":"o/a"}}}}}}"#),
            );
            assert!(
                read_foreign_lock(&p).is_ok(),
                "version {v} must be readable"
            );
        }
    }

    #[test]
    fn folder_hash_is_recorded_but_never_used_as_a_content_digest() {
        let p = tmp(
            "folderhash",
            r#"{"version":3,"skills":{"a":{"source":"o/a","skillFolderHash":"deadbeef"}}}"#,
        );
        let entries = read_foreign_lock(&p).unwrap_or_default();
        assert_eq!(entries[0].folder_hash.as_deref(), Some("deadbeef"));
        assert!(
            entries[0].digest.is_none(),
            "a tree SHA proves nothing about content here"
        );
    }

    #[test]
    fn unknown_lockfile_name_is_rejected_clearly() {
        let d = std::env::temp_dir().join("sg-import-unknown");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_default();
        let p = d.join("Cargo.lock");
        std::fs::write(&p, "{}").unwrap_or_default();
        let err = read_foreign_lock(&p).unwrap_err();
        assert!(err.contains("unrecognised"), "{err}");
    }

    #[test]
    fn package_json_only_imports_agent_skills() {
        let d = std::env::temp_dir().join("sg-import-pkg");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_default();

        let plain = d.join("package.json");
        std::fs::write(&plain, r#"{"name":"app","version":"1.0.0"}"#).unwrap_or_default();
        assert!(read_foreign_lock(&plain).unwrap_or_default().is_empty());

        let skill = d.join("skill-package.json");
        std::fs::write(
            &skill,
            r#"{"name":"my-skill","version":"1.2.0","keywords":["agent-skill"]}"#,
        )
        .unwrap_or_default();
        let renamed = d.join("package.json");
        std::fs::rename(&skill, &renamed).unwrap_or_default();
        let entries = read_foreign_lock(&renamed).unwrap_or_default();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(read_foreign_lock(Path::new("/nonexistent/skills-lock.json")).is_err());
    }
}
