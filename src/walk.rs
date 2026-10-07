//! Safe directory traversal.
//!
//! Everything here defends against hostile input (docs/THREAT_MODEL.md T11–T13):
//! symlink escapes, traversal depth bombs, inode exhaustion, oversized files
//! and binaries that are not valid UTF-8.
//!
//! Invariant S6: the only way to turn a skill-relative string into a path that
//! gets read is [`resolve_safe_path`].

use crate::models::{ArtifactKind, SourceFile};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub mod limits {
    /// Maximum directory depth below the skill root.
    pub const MAX_DEPTH: usize = 12;
    /// Maximum files collected per skill.
    pub const MAX_FILES: usize = 10_000;
    /// Maximum bytes read from a single file.
    pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
    /// Maximum total bytes read per skill.
    pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
}

/// Directories that are never interesting and can hide payloads cheaply.
const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    "vendor",
];

/// Extensions we treat as executable code for capability purposes.
const SCRIPT_EXT: &[&str] = &[
    "sh", "bash", "zsh", "fish", "ps1", "psm1", "cmd", "bat", "py", "rb", "pl", "php", "js", "mjs",
    "cjs", "jsx", "ts", "tsx", "go", "rs", "lua", "awk", "ksh",
];

const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "environment.yml",
];

/// Resolve a skill-relative path, refusing anything that escapes the root.
///
/// Returns `Err` with a human-readable reason rather than a path. Callers turn
/// the `Err` into a finding; they must not read the file.
pub fn resolve_safe_path(root: &Path, rel: &str) -> Result<PathBuf, String> {
    // Refuse Windows-style absolute paths even on Unix. `C:/Windows` is a valid
    // *relative* path on Linux (a file literally named `C:` in a subdirectory),
    // so `Path::is_absolute` returns false and the escape would slip through on
    // one platform and be caught on another. A skill has no legitimate reason to
    // name a drive or a UNC share, so a platform-independent refusal is both
    // safer and reproducible (see issue #6: sgdir-v1 makes a portability
    // promise, and path handling is part of it).
    if looks_like_windows_absolute(rel) {
        return Err(format!("absolute path is not readable: {rel}"));
    }
    // `..\..\etc` is one component on Unix and two on Windows. Normalise the
    // separator for the escape check only, so the same tree is judged the same
    // way everywhere. This never turns a safe path into an unsafe one.
    if rel.split(['/', '\\']).any(|seg| seg == "..") {
        return Err(format!("path escapes the skill root: {rel}"));
    }
    let candidate = Path::new(rel);
    if candidate.is_absolute() {
        return Err(format!("absolute path is not readable: {rel}"));
    }
    let mut out = root.to_path_buf();
    for comp in candidate.components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("path escapes the skill root: {rel}"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute path is not readable: {rel}"));
            }
        }
    }
    if !out.starts_with(root) {
        return Err(format!("path escapes the skill root: {rel}"));
    }
    Ok(out)
}

/// A drive-letter (`C:...`) or UNC (`\\server\share`) path, on any OS.
fn looks_like_windows_absolute(rel: &str) -> bool {
    let b = rel.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return true;
    }
    rel.starts_with("\\\\")
}

/// What the walker found, including things it refused to follow.
#[derive(Debug, Default)]
pub struct Walked {
    pub files: Vec<SourceFile>,
    /// `(rel, reason)` for symlinks pointing outside the skill.
    pub symlink_escapes: Vec<(String, String)>,
    pub truncated_depth: bool,
    pub hit_file_cap: bool,
    pub hit_byte_cap: bool,
}

/// Walk a skill directory and classify every file.
///
/// Symlinks are never followed (`follow_links(false)`). A symlink whose target
/// resolves outside the root is recorded, because `scripts/link -> ~/.ssh` is
/// an exfiltration primitive even though we refuse to read it.
pub fn walk_skill(root: &Path) -> Walked {
    let mut out = Walked::default();
    let mut total: u64 = 0;
    let root_canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .max_depth(limits::MAX_DEPTH)
        .into_iter();

    for entry in walker {
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        let depth = path
            .strip_prefix(root)
            .map_or(0, |p| p.components().count());
        if depth > limits::MAX_DEPTH {
            out.truncated_depth = true;
            continue;
        }

        let rel = rel_path(root, path);

        // Refuse symlinks that point outside the skill.
        if entry.file_type().is_symlink() {
            let target = std::fs::read_link(path).unwrap_or_default();
            let escapes = match std::fs::canonicalize(&target) {
                Ok(t) => !t.starts_with(&root_canon),
                Err(_) => target.is_absolute(),
            };
            if escapes {
                out.symlink_escapes
                    .push((rel, target.to_string_lossy().to_string()));
            }
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        // Directory pruning by name.
        if path
            .components()
            .any(|c| EXCLUDED_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref()))
        {
            continue;
        }

        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if md.len() > limits::MAX_FILE_BYTES {
            out.files.push(SourceFile {
                path: path.to_path_buf(),
                rel,
                kind: classify(path),
                bytes: Vec::new(),
                scanned: false,
                note: Some(format!(
                    "skipped: file is {} bytes, limit is {}",
                    md.len(),
                    limits::MAX_FILE_BYTES
                )),
            });
            continue;
        }

        if out.files.len() >= limits::MAX_FILES {
            out.hit_file_cap = true;
            break;
        }
        if total + md.len() > limits::MAX_TOTAL_BYTES {
            out.hit_byte_cap = true;
            break;
        }

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                out.files.push(SourceFile {
                    path: path.to_path_buf(),
                    rel,
                    kind: classify(path),
                    bytes: Vec::new(),
                    scanned: false,
                    note: Some(format!("unreadable: {e}")),
                });
                continue;
            }
        };
        total += bytes.len() as u64;

        let (scanned, note) = if std::str::from_utf8(&bytes).is_err() {
            (false, Some("skipped: not valid UTF-8".to_owned()))
        } else {
            (true, None)
        };

        out.files.push(SourceFile {
            path: path.to_path_buf(),
            rel,
            kind: classify(path),
            bytes,
            scanned,
            note,
        });
    }

    out.files.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Classify a file. `SKILL.md` is split by the parser into frontmatter and
/// markdown; everything else is classified by name and extension.
pub fn classify(path: &Path) -> ArtifactKind {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name == "skill.md" {
        return ArtifactKind::Markdown;
    }
    if MANIFEST_FILES.contains(&name.as_str()) {
        return ArtifactKind::Manifest;
    }
    if name.starts_with("license") || name.starts_with("copying") || name == "notice" {
        return ArtifactKind::Metadata;
    }
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if SCRIPT_EXT.contains(&ext.as_str()) {
        return ArtifactKind::Script;
    }
    if ext == "md" || ext == "markdown" {
        ArtifactKind::Markdown
    } else {
        ArtifactKind::Metadata
    }
}

/// Skill directories found directly under a root, deduplicated.
///
/// Used by `skillguard scan <dir>` to handle a directory that contains several
/// skills, and by corpus tooling. Symlinked skill dirs are not followed.
pub fn discover_skill_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    if root.join("SKILL.md").is_file() {
        out.insert(root.to_path_buf());
        return out.into_iter().collect();
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() && p.join("SKILL.md").is_file() {
            out.insert(p);
        }
    }
    // Nested: <root>/<category>/<skill>/SKILL.md
    if out.is_empty() {
        let Ok(rd) = std::fs::read_dir(root) else {
            return Vec::new();
        };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let Ok(inner) = std::fs::read_dir(&p) else {
                continue;
            };
            for e2 in inner.flatten() {
                let p2 = e2.path();
                if p2.is_dir() && p2.join("SKILL.md").is_file() {
                    out.insert(p2);
                }
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-test-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap_or_default();
        d
    }

    #[test]
    fn rejects_escaping_paths() {
        let root = Path::new("/tmp/skill");
        assert!(resolve_safe_path(root, "../../etc/passwd").is_err());
        assert!(resolve_safe_path(root, "/etc/passwd").is_err());
        assert!(resolve_safe_path(root, "C:/Windows").is_err());
    }

    #[test]
    fn rejects_windows_style_escapes_on_every_platform() {
        // The same hostile input must be refused identically on Linux, macOS
        // and Windows; #6 exists because it was not.
        let root = Path::new("/tmp/skill");
        assert!(resolve_safe_path(root, "C:/Windows/win.ini").is_err());
        assert!(resolve_safe_path(root, "c:\\Windows\\win.ini").is_err());
        assert!(resolve_safe_path(root, "\\\\server\\share\\x").is_err());
        assert!(resolve_safe_path(root, "..\\..\\etc").is_err());
        assert!(resolve_safe_path(root, "scripts\\..\\..\\etc").is_err());
        // A backslash inside a legitimate filename is still allowed.
        assert!(resolve_safe_path(root, "notes/weird\\name.txt").is_ok());
    }

    #[test]
    fn accepts_normal_relative_paths() {
        let root = Path::new("/tmp/skill");
        assert!(resolve_safe_path(root, "scripts/setup.sh").is_ok());
        assert!(resolve_safe_path(root, "./references/guide.md").is_ok());
    }

    #[test]
    fn rejects_parent_dir_even_when_it_would_stay_inside() {
        // A skill has no legitimate reason to walk upwards, so `..` is refused
        // outright rather than normalised and re-checked. Refusing is simpler
        // to reason about and cannot be defeated by a future refactor.
        let root = Path::new("/tmp/skill");
        assert!(resolve_safe_path(root, "scripts/../scripts/a.py").is_err());
        assert!(resolve_safe_path(root, "a/../../b").is_err());
    }

    #[test]
    fn classifies_by_name_and_extension() {
        assert_eq!(classify(Path::new("a/SKILL.md")), ArtifactKind::Markdown);
        assert_eq!(
            classify(Path::new("a/package.json")),
            ArtifactKind::Manifest
        );
        assert_eq!(classify(Path::new("a/x.sh")), ArtifactKind::Script);
        assert_eq!(classify(Path::new("a/x.py")), ArtifactKind::Script);
        assert_eq!(classify(Path::new("a/LICENSE")), ArtifactKind::Metadata);
        assert_eq!(classify(Path::new("a/notes.txt")), ArtifactKind::Metadata);
    }

    #[test]
    fn walks_and_prunes_noise_dirs() {
        let d = tmp("walk");
        fs::write(d.join("SKILL.md"), "---\nname: t\n---\n").unwrap_or_default();
        fs::create_dir_all(d.join("scripts")).unwrap_or_default();
        fs::write(d.join("scripts/run.sh"), "echo hi").unwrap_or_default();
        fs::create_dir_all(d.join("node_modules/pkg")).unwrap_or_default();
        fs::write(d.join("node_modules/pkg/evil.js"), "rm -rf /").unwrap_or_default();
        let w = walk_skill(&d);
        let rels: Vec<_> = w.files.iter().map(|f| f.rel.as_str()).collect();
        assert!(rels.contains(&"SKILL.md"));
        assert!(rels.contains(&"scripts/run.sh"));
        assert!(!rels.iter().any(|r| r.contains("node_modules")), "{rels:?}");
    }

    #[test]
    fn skips_binary_and_oversized_files_with_a_reason() {
        let d = tmp("binary");
        fs::write(d.join("SKILL.md"), "x").unwrap_or_default();
        fs::write(d.join("blob.js"), [0xff, 0xfe, 0x00, 0x01]).unwrap_or_default();
        fs::write(d.join("huge.js"), vec![b'a'; 5 * 1024 * 1024]).unwrap_or_default();
        let w = walk_skill(&d);
        let blob = w
            .files
            .iter()
            .find(|f| f.rel == "blob.js")
            .expect("blob listed");
        assert!(!blob.scanned);
        assert!(
            blob.note.as_deref().unwrap_or("").contains("UTF-8"),
            "{:?}",
            blob.note
        );
        let huge = w
            .files
            .iter()
            .find(|f| f.rel == "huge.js")
            .expect("huge listed");
        assert!(!huge.scanned, "a 5 MiB file is over the 4 MiB limit");
        assert!(huge.note.is_some());
    }

    #[test]
    fn records_symlink_escapes_without_following() {
        let d = tmp("symlink");
        fs::write(d.join("SKILL.md"), "x").unwrap_or_default();
        fs::create_dir_all(d.join("scripts")).unwrap_or_default();
        // Creating a symlink on Windows can require elevation; skip rather
        // than fail when the OS refuses.
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file("C:/Windows/win.ini", d.join("scripts/link")).is_err()
        {
            return;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", d.join("scripts/link")).unwrap();
        let w = walk_skill(&d);
        assert!(
            w.files.iter().all(|f| f.rel != "scripts/link"),
            "a symlink must never be read as a file"
        );
        assert!(
            !w.symlink_escapes.is_empty(),
            "an escaping symlink must be recorded"
        );
    }

    #[test]
    fn discovers_skill_dirs() {
        let d = tmp("discover");
        // A root that is itself a skill resolves to just that skill.
        fs::write(d.join("SKILL.md"), "x").unwrap_or_default();
        fs::create_dir_all(d.join("b")).unwrap_or_default();
        fs::write(d.join("b/SKILL.md"), "y").unwrap_or_default();
        fs::create_dir_all(d.join("not-a-skill")).unwrap_or_default();
        assert_eq!(discover_skill_dirs(&d).len(), 1);

        // A container directory yields each nested skill.
        let c = tmp("discover-nested");
        fs::create_dir_all(c.join("b")).unwrap_or_default();
        fs::write(c.join("b/SKILL.md"), "y").unwrap_or_default();
        fs::create_dir_all(c.join("c")).unwrap_or_default();
        fs::write(c.join("c/SKILL.md"), "z").unwrap_or_default();
        assert_eq!(discover_skill_dirs(&c).len(), 2);
    }
}
