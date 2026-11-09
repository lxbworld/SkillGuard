//! Embedded examples for `skillguard demo`.
//!
//! A first-time user should not have to find, clone and vet a real skill before
//! they can see what the tool does. These two examples live inside the binary,
//! are written to a temporary directory at runtime, and are scanned through the
//! ordinary code path. Nothing is downloaded and nothing is executed.
//!
//! The content is deliberately a copy of two fixtures rather than an
//! `include_str!` of `tests/fixtures/`: the crate excludes fixtures from the
//! published package, so referencing them here would break `cargo install`.
//! `embedded_examples_still_trip_their_rules` keeps the copy honest.

use std::path::{Path, PathBuf};

pub struct DemoSkill {
    /// Also the directory name, which is the name the report prints.
    pub name: &'static str,
    pub files: &'static [(&'static str, &'static str)],
}

pub const SKILLS: &[DemoSkill] = &[
    DemoSkill {
        name: "quick-setup",
        files: &[
            ("SKILL.md", include_str!("demo/quick-setup/SKILL.md")),
            (
                "scripts/setup.sh",
                include_str!("demo/quick-setup/scripts/setup.sh"),
            ),
        ],
    },
    DemoSkill {
        name: "weather-report",
        files: &[
            ("SKILL.md", include_str!("demo/weather-report/SKILL.md")),
            (
                "scripts/fetch.py",
                include_str!("demo/weather-report/scripts/fetch.py"),
            ),
        ],
    },
];

/// Write every example under `root`, returning the skill directories.
pub fn write_all(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs = Vec::with_capacity(SKILLS.len());
    for skill in SKILLS {
        let dir = root.join(skill.name);
        for (rel, body) in skill.files {
            let path = dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            std::fs::write(&path, body)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        }
        dirs.push(dir);
    }
    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_examples_still_trip_their_rules() {
        let root = std::env::temp_dir().join(format!("sg-demo-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs = write_all(&root).expect("write demo skills");

        let quick = crate::scan::scan_skill(&dirs[0]);
        assert_eq!(quick.skill_name, "quick-setup");
        assert!(
            quick
                .findings
                .iter()
                .any(|f| f.rule.0 == "DL_CHAIN_FETCH_EXECUTE"),
            "the fetch->execute chain must still be reported: {:#?}",
            quick.findings
        );

        let weather = crate::scan::scan_skill(&dirs[1]);
        assert_eq!(weather.skill_name, "weather-report");
        assert!(
            weather.diff.undeclared() >= 1,
            "the demo must show an undeclared capability: {:#?}",
            weather.diff
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
