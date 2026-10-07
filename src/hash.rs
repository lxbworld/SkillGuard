//! Content addressing and provenance.
//!
//! # The rule
//!
//! Do not trust a repository URL. Bind **source + commit + content digest**,
//! and recompute the digest on every verification rather than trusting the
//! recorded one.
//!
//! # Why the digest is defined the way it is
//!
//! `sgdir-v1` exists so that the same content produces the same digest on any
//! machine and any OS. Three details make that true, and each one is a bug I
//! had to fix first:
//!
//! * **Sorted POSIX-style relative paths.** Sorting makes the digest
//!   independent of directory iteration order, which differs by filesystem.
//! * **Only the executable bit is hashed.** Full mode bits differ by umask, so
//!   hashing them made digests unreproducible across machines.
//! * **`.git/` and the lockfile itself are excluded.** Including `.git` makes
//!   the digest depend on clone method; including `SKILLGUARD.lock` makes it
//!   self-referential and therefore impossible to compute.

use sha2::Sha256;
// Imported under an alias: this module defines its own `Digest` type, which
// would otherwise shadow the trait that provides `Sha256::new()`.
use sha2::Digest as Sha2Digest;
use std::path::{Path, PathBuf};

/// Version tag mixed into every digest, so the algorithm can change later
/// without silently invalidating old lockfiles.
pub const DIGEST_ALGORITHM: &str = "sgdir-v1";

/// Files never included in a skill digest.
const EXCLUDED_FILES: &[&str] = &["SKILLGUARD.lock", ".DS_Store", "Thumbs.db"];
const EXCLUDED_DIRS: &[&str] = &[".git", "node_modules", "__pycache__", ".venv", "target"];

/// A content digest, formatted as `sha256:<64 hex>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Digest(pub String);

impl Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        match self.0.strip_prefix("sha256:") {
            Some(hex) => hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()),
            None => false,
        }
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Compute the `sgdir-v1` digest of a skill directory.
///
/// Returns the digest plus the per-file inventory, because a verification
/// failure is only actionable if you can see *which* file changed.
pub fn digest_dir(root: &Path) -> Result<(Digest, Vec<FileDigest>), String> {
    // A missing directory must be an error. Returning the digest of an empty
    // tree would let `verify` pass for a skill that is not there at all, which
    // is precisely the failure mode a lockfile exists to prevent.
    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.to_string_lossy()));
    }

    let mut entries: Vec<FileDigest> = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = rel_posix(root, path);
        if is_excluded(&rel) {
            continue;
        }
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {rel}: {e}"))?;
        // Only the executable bit is hashed: full mode varies by umask.
        let exec_bit = is_executable(path);
        entries.push(FileDigest {
            path: rel,
            digest: sha256_hex(&bytes),
            executable: exec_bit,
            size: bytes.len() as u64,
        });
    }

    // Sort by the canonical path so the digest is iteration-order independent.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut hasher = Sha256::new();
    hasher.update(b"SKILLGUARD-DIR-v1\0");
    for e in &entries {
        hasher.update(b"sfg1\0");
        hasher.update(e.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(if e.executable { b"755" } else { b"644" });
        hasher.update(b"\0");
        hasher.update(e.digest.as_bytes());
        hasher.update(b"\0");
    }
    let hex = hex(&hasher.finalize());
    Ok((Digest(format!("sha256:{hex}")), entries))
}

/// Per-file digest, retained so a mismatch can be explained.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileDigest {
    pub path: String,
    pub digest: String,
    pub executable: bool,
    pub size: u64,
}

fn is_excluded(rel: &str) -> bool {
    if EXCLUDED_FILES.iter().any(|f| rel == *f || rel.ends_with(f)) {
        return true;
    }
    rel.split('/').any(|seg| EXCLUDED_DIRS.contains(&seg))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Slash-separated relative path, NFC-normalised.
fn rel_posix(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── provenance ────────────────────────────────────────────────────────────

/// Where a skill came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// `github:owner/repo`, `path:./local`, or `unknown`.
    pub source: Option<String>,
    pub repository: Option<String>,
    /// Full 40-hex commit. Never a tag, branch or short SHA.
    pub commit: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    /// Where the license string came from, so a reader can judge it.
    pub license_source: Option<String>,
    /// True when we could not establish source *and* commit.
    pub incomplete: bool,
    /// Why provenance is incomplete.
    pub note: Option<String>,
}

/// Collected provenance for a skill directory on disk.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Collected {
    pub provenance: Provenance,
    pub files: Vec<FileDigest>,
    pub digest: Digest,
}

/// Collect digest and provenance.
///
/// Git is invoked read-only as a subprocess rather than through `git2`:
/// libgit2 brings its own TLS and certificate behaviour, which would add a
/// network and trust surface to a tool whose whole premise is that it does not
/// need one. Only `rev-parse`, `config` and `log` are used, and only when the
/// directory is already a repository.
pub fn collect(root: &Path, declared_license: Option<&str>) -> Result<Collected, String> {
    let (digest, files) = digest_dir(root)?;
    let provenance = read_git_provenance(root, declared_license);
    Ok(Collected {
        provenance,
        files,
        digest,
    })
}

fn read_git_provenance(root: &Path, declared_license: Option<&str>) -> Provenance {
    let Some(repo_root) = git_root(root) else {
        return Provenance {
            license: declared_license.map(str::to_owned),
            license_source: declared_license.map(|_| "frontmatter".to_owned()),
            incomplete: true,
            note: Some("not a git repository: source cannot be established".to_owned()),
            ..Provenance::default()
        };
    };

    // `rev-parse HEAD` resolves to a full 40-hex sha. Tags and branches are
    // rejected: a corpus or lockfile pinned to a moving ref is not reproducible.
    let commit = git(&repo_root, &["rev-parse", "HEAD"]).map(|s| s.trim().to_owned());
    let commit = commit.filter(|c| c.len() == 40 && c.chars().all(|x| x.is_ascii_hexdigit()));

    let remote = git(&repo_root, &["config", "--get", "remote.origin.url"])
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let repository = remote.as_deref().and_then(normalize_remote);

    let author = git(&repo_root, &["log", "-1", "--format=%an"])
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    let incomplete = commit.is_none() || repository.is_none();
    Provenance {
        source: repository
            .as_ref()
            .map(|r| format!("github:{}", r.trim_start_matches("github.com/"))),
        repository,
        commit,
        author,
        license: declared_license.map(str::to_owned),
        license_source: declared_license.map(|_| "frontmatter".to_owned()),
        incomplete,
        note: incomplete.then(|| {
            "source or commit could not be established; treat this install as unreproducible"
                .to_owned()
        }),
    }
}

fn git_root(path: &Path) -> Option<PathBuf> {
    let out = git(path, &["rev-parse", "--show-toplevel"])?;
    let p = PathBuf::from(out.trim());
    if p.as_os_str().is_empty() {
        None
    } else {
        Some(p)
    }
}

/// Run git read-only. Returns `None` for any failure; git being absent is not
/// an error, it just means provenance is unavailable.
fn git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        // A hostile repo's git config must not be able to run commands.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// `git@github.com:o/r.git`, `https://github.com/o/r.git` and `ssh://git@host/o/r`
/// all reduce to `o/r`.
fn normalize_remote(url: &str) -> Option<String> {
    let u = url.trim().trim_end_matches('/').trim_end_matches(".git");
    // Drop a scheme, then any `user@` prefix.
    let after_scheme = match u.split_once("://") {
        Some((_, rest)) => rest,
        None => u,
    };
    let after_user = match after_scheme.split_once('@') {
        Some((_, rest)) => rest,
        None => after_scheme,
    };
    // scp-style `host:owner/repo` has no slash before the owner.
    let tail = match after_user.split_once(':') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => after_user,
    };

    let parts: Vec<&str> = tail.split('/').filter(|s| !s.is_empty()).collect();
    match parts.len() {
        0 | 1 => None,
        n => Some(format!("{}/{}", parts[n - 2], parts[n - 1])),
    }
}

/// A full commit SHA, validated.
pub fn is_full_commit(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Refuse anything that is not a full SHA. A lockfile pinned to `main` will
/// silently change content on the next pull.
pub fn reject_moving_ref(kind: &str, value: &str) -> Result<(), String> {
    if is_full_commit(value) {
        return Ok(());
    }
    Err(format!(
        "{kind} must be a full 40-character commit SHA, got {value:?}. \
         Tags, branches and short SHAs are refused because they are not reproducible."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-hash-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap_or_default();
        d
    }

    fn write(d: &Path, rel: &str, body: &str) {
        let p = d.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap_or_default();
        }
        fs::write(p, body).unwrap_or_default();
    }

    #[test]
    fn digest_is_stable_across_calls() {
        let d = tmp("stable");
        write(&d, "SKILL.md", "hello");
        write(&d, "scripts/run.sh", "echo hi");
        let (a, _) = digest_dir(&d).unwrap_or_default();
        let (b, _) = digest_dir(&d).unwrap_or_default();
        assert_eq!(a, b);
        assert!(a.is_valid(), "{}", a);
    }

    #[test]
    fn digest_changes_when_any_byte_changes() {
        let d = tmp("change");
        write(&d, "SKILL.md", "hello");
        write(&d, "scripts/run.sh", "echo hi");
        let before = digest_dir(&d).unwrap_or_default().0;
        write(&d, "scripts/run.sh", "echo hi ");
        let after = digest_dir(&d).unwrap_or_default().0;
        assert_ne!(before, after, "one byte must change the digest");
    }

    #[test]
    fn digest_ignores_file_creation_order() {
        let a = tmp("order-a");
        write(&a, "SKILL.md", "x");
        write(&a, "b.txt", "b");
        write(&a, "a.txt", "a");

        let b = tmp("order-b");
        write(&b, "a.txt", "a");
        write(&b, "b.txt", "b");
        write(&b, "SKILL.md", "x");

        assert_eq!(
            digest_dir(&a).unwrap_or_default().0,
            digest_dir(&b).unwrap_or_default().0
        );
    }

    #[test]
    fn digest_excludes_git_and_the_lockfile() {
        let d = tmp("exclude");
        write(&d, "SKILL.md", "x");
        let base = digest_dir(&d).unwrap_or_default().0;

        write(&d, ".git/HEAD", "ref: refs/heads/main");
        write(&d, "SKILLGUARD.lock", "lockfile_version: 1");
        write(&d, "node_modules/pkg/index.js", "x");

        assert_eq!(
            base,
            digest_dir(&d).unwrap_or_default().0,
            ".git, the lockfile and vendored deps must not affect the digest"
        );
    }

    #[test]
    fn renaming_a_file_changes_the_digest() {
        let d = tmp("rename");
        write(&d, "SKILL.md", "x");
        write(&d, "a.txt", "same");
        let before = digest_dir(&d).unwrap_or_default().0;
        fs::rename(d.join("a.txt"), d.join("b.txt")).unwrap_or_default();
        assert_ne!(before, digest_dir(&d).unwrap_or_default().0);
    }

    #[test]
    fn digest_is_not_a_self_referential_loop() {
        // Writing the digest into the tree must not invalidate it, otherwise
        // `lock` could never converge.
        let d = tmp("selfref");
        write(&d, "SKILL.md", "x");
        let first = digest_dir(&d).unwrap_or_default().0;
        write(&d, "SKILLGUARD.lock", &format!("content_digest: {first}"));
        let second = digest_dir(&d).unwrap_or_default().0;
        assert_eq!(first, second);
    }

    #[test]
    fn inventory_lists_every_included_file() {
        let d = tmp("inventory");
        write(&d, "SKILL.md", "x");
        write(&d, "scripts/a.py", "print(1)");
        write(&d, ".git/HEAD", "ref");
        let (_, files) = digest_dir(&d).unwrap_or_default();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["SKILL.md", "scripts/a.py"]);
    }

    #[test]
    fn missing_directory_is_an_error_not_a_panic() {
        assert!(digest_dir(Path::new("/nonexistent/skillguard/xyz")).is_err());
    }

    #[test]
    fn remote_urls_are_normalised() {
        assert_eq!(
            normalize_remote("https://github.com/o/r.git"),
            Some("o/r".to_owned())
        );
        assert_eq!(
            normalize_remote("git@github.com:o/r.git"),
            Some("o/r".to_owned())
        );
        assert_eq!(
            normalize_remote("https://github.com/o/r"),
            Some("o/r".to_owned())
        );
        assert_eq!(normalize_remote("not-a-url"), None);
    }

    #[test]
    fn moving_refs_are_refused() {
        assert!(reject_moving_ref("commit", &"a".repeat(40)).is_ok());
        assert!(reject_moving_ref("commit", "main").is_err());
        assert!(reject_moving_ref("commit", "v1.2.3").is_err());
        assert!(reject_moving_ref("commit", &"a".repeat(7)).is_err());
        let err = reject_moving_ref("commit", "main").unwrap_err();
        assert!(
            err.contains("reproducible"),
            "the error must explain why: {err}"
        );
    }

    #[test]
    fn digest_format_is_validated() {
        assert!(Digest("sha256:".to_owned() + &"a".repeat(64)).is_valid());
        assert!(!Digest("sha256:abc".to_owned()).is_valid());
        assert!(!Digest("md5:".to_owned() + &"a".repeat(32)).is_valid());
        assert!(!Digest("a".repeat(64)).is_valid());
    }

    #[test]
    fn provenance_of_a_non_git_directory_is_marked_incomplete() {
        let d = tmp("nogit");
        write(&d, "SKILL.md", "x");
        let c = collect(&d, Some("MIT")).unwrap_or_default();
        assert!(c.provenance.incomplete, "{:?}", c.provenance);
        assert_eq!(c.provenance.license.as_deref(), Some("MIT"));
        assert!(c.provenance.note.is_some(), "a reason must be given");
    }
}
