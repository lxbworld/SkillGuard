//! Tests for the distribution path: the installer that every GitHub Action and
//! release archive goes through.
//!
//! The installer is security-relevant: it decides whether a downloaded binary
//! is trusted. It must verify the checksum, and a mismatch must never be
//! papered over by a fallback build (issue #4).
//!
//! Unix-only: the fixtures use a shell-script stand-in for the binary, and the
//! Windows path is exercised by the release workflow rather than here.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn installer() -> PathBuf {
    repo_root().join("action/install.sh")
}

fn platform_asset() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "skillguard-linux-x86_64.tar.gz",
        ("linux", "aarch64") => "skillguard-linux-aarch64.tar.gz",
        ("macos", "x86_64") => "skillguard-macos-x86_64.tar.gz",
        ("macos", "aarch64") => "skillguard-macos-aarch64.tar.gz",
        _ => "",
    }
    .to_owned()
}

fn sha256(path: &Path) -> String {
    let (prog, args) = if Command::new("shasum").arg("--version").output().is_ok() {
        ("shasum", vec!["-a", "256"])
    } else {
        ("sha256sum", vec![])
    };
    let out = Command::new(prog)
        .args(args)
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("run {prog}: {e}"));
    assert!(out.status.success(), "{prog} failed");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned()
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sg-dist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

/// Build a fake release: a tarball containing a `skillguard` that prints a
/// version, plus its checksum file. `tag` must be unique per test: the tests
/// run in parallel and must not share a release directory.
fn fake_release(tag: &str, version: &str) -> PathBuf {
    let base = tmpdir(&format!("release-{tag}"));
    let asset = platform_asset();
    assert!(!asset.is_empty(), "no asset name for this platform");

    let stage = tmpdir(&format!("stage-{tag}"));
    std::fs::write(
        stage.join("skillguard"),
        "#!/bin/sh\necho \"skillguard fake\"\n",
    )
    .expect("write fake binary");

    let archive = base.join(version).join(&asset);
    std::fs::create_dir_all(archive.parent().expect("version dir")).expect("mkdir");
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args(["-C"])
        .arg(&stage)
        .arg("skillguard")
        .status()
        .expect("run tar");
    assert!(status.success(), "tar failed");

    let digest = sha256(&archive);
    let mut checksum = archive.clone().into_os_string();
    checksum.push(".sha256");
    std::fs::write(PathBuf::from(checksum), format!("{digest}  {asset}\n"))
        .expect("write checksum");
    base
}

fn install(base: &Path, version: &str, dest: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(installer())
        .arg(version)
        .arg(dest)
        .env(
            "SKILLGUARD_RELEASE_BASE",
            format!("file://{}", base.display()),
        )
        .output()
        .expect("run install.sh")
}

#[test]
fn a_verified_asset_is_installed_and_runs() {
    let version = "v0.1.0";
    let base = fake_release("ok", version);
    let dest = tmpdir("install-ok");
    let out = install(&base, version, &dest);
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("bin/skillguard").exists(), "binary not installed");

    let run = Command::new(dest.join("bin/skillguard"))
        .arg("--version")
        .output()
        .expect("run installed binary");
    assert!(run.status.success());
}

#[test]
fn a_tampered_asset_is_refused_and_nothing_is_installed() {
    let version = "v0.1.0";
    let base = fake_release("tampered", version);
    let asset = platform_asset();
    let archive = base.join(version).join(&asset);
    // Flip one byte after the checksum was computed.
    let mut bytes = std::fs::read(&archive).expect("read archive");
    bytes.push(b'x');
    std::fs::write(&archive, bytes).expect("tamper");

    let dest = tmpdir("install-tampered");
    let out = install(&base, version, &dest);
    assert!(
        !out.status.success(),
        "a checksum mismatch must fail the install"
    );
    assert!(
        !dest.join("bin/skillguard").exists(),
        "a tampered artifact must never be installed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("checksum mismatch"),
        "the failure must say why: {stderr}"
    );
}

#[test]
fn a_missing_release_falls_back_to_a_source_build() {
    // The fallback is for platforms without an asset and for pre-release
    // checkouts. It must not be reached on a checksum mismatch, which the
    // tampering test covers. `cargo` is removed from PATH so the fallback is
    // observable without actually rebuilding the crate in a test.
    let dest = tmpdir("install-fallback");
    let base = tmpdir("missing-release");
    let out = Command::new("/bin/bash")
        .arg(installer())
        .arg("v9.9.9")
        .arg(&dest)
        .env(
            "SKILLGUARD_RELEASE_BASE",
            format!("file://{}", base.display()),
        )
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run install.sh");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("falling back"),
        "a missing release must fall back, not fail silently: {stderr}"
    );
    assert!(
        stderr.contains("cargo is not available") || out.status.success(),
        "the fallback should reach the source build: {stderr}"
    );
}

/// The README documents `curl … | bash`, and that shape has no script
/// directory, so the front-door installer cannot delegate to a relative path.
/// It was broken exactly that way until issue #18: `BASH_SOURCE[0]: unbound
/// variable`, then a lookup of `./action/install.sh` under the caller's cwd.
#[test]
fn the_piped_installer_fetches_the_real_one_from_the_same_ref() {
    let version = "v0.1.0";
    let base = fake_release("piped", version);

    // Stand in for raw.githubusercontent.com: the installer is fetched from
    // `<raw>/<ref>/action/install.sh`, so the fake tree has to hold it.
    let raw = tmpdir("piped-raw");
    let refdir = raw.join(version).join("action");
    std::fs::create_dir_all(&refdir).expect("mkdir raw tree");
    std::fs::copy(installer(), refdir.join("install.sh")).expect("copy installer");

    let dest = tmpdir("install-piped");
    // Run from an unrelated directory, like a first-time user does: from the
    // repository root the broken version would find `./action/install.sh` by
    // accident and the test would pass on both.
    let cwd = tmpdir("piped-cwd");
    let script = std::fs::File::open(repo_root().join("install.sh")).expect("open install.sh");
    let out = Command::new("bash")
        .arg("-s")
        .arg("--")
        .arg(version)
        .arg(&dest)
        .current_dir(&cwd)
        .stdin(script)
        .env("SKILLGUARD_RAW_BASE", format!("file://{}", raw.display()))
        .env(
            "SKILLGUARD_RELEASE_BASE",
            format!("file://{}", base.display()),
        )
        .output()
        .expect("run piped install.sh");

    assert!(
        out.status.success(),
        "the documented one-liner must work: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        dest.join("bin/skillguard").exists(),
        "binary not installed from the piped path"
    );
    let run = Command::new(dest.join("bin/skillguard"))
        .arg("--version")
        .output()
        .expect("run installed binary");
    assert!(run.status.success());
}

/// A first-time user runs the one-liner with no arguments beyond the version.
/// The binary must land somewhere that survives a reboot and is on PATH, not in
/// a temp directory the CI installer defaults to.
#[test]
fn the_front_door_installs_into_the_user_prefix_by_default() {
    let version = "v0.1.0";
    let base = fake_release("prefix", version);
    let raw = tmpdir("prefix-raw");
    let refdir = raw.join(version).join("action");
    std::fs::create_dir_all(&refdir).expect("mkdir raw tree");
    std::fs::copy(installer(), refdir.join("install.sh")).expect("copy installer");

    let home = tmpdir("prefix-home");
    let cwd = tmpdir("prefix-cwd");
    let script = std::fs::File::open(repo_root().join("install.sh")).expect("open install.sh");
    let out = Command::new("bash")
        .arg("-s")
        .arg("--")
        .arg(version)
        .current_dir(&cwd)
        .stdin(script)
        .env("HOME", &home)
        .env("SKILLGUARD_RAW_BASE", format!("file://{}", raw.display()))
        .env(
            "SKILLGUARD_RELEASE_BASE",
            format!("file://{}", base.display()),
        )
        .output()
        .expect("run piped install.sh");

    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        home.join(".local/bin/skillguard").exists(),
        "the default prefix must be the user's, not a temp dir: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // And it must say what to do when that directory is not on PATH.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not on your PATH"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
