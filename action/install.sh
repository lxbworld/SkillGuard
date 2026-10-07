#!/usr/bin/env bash
#
# Install SkillGuard on the current machine.
#
# Two paths, because both matter:
#   1. If a version is given, download the prebuilt release asset for this
#      platform and verify its SHA-256. This is the low-friction path a
#      composite action and a first-time user should take.
#   2. Otherwise build the checkout this script lives in from source. This is
#      the fallback that keeps the action working before a release exists and
#      on platforms without a prebuilt asset.
#
# It never installs a binary it has not verified: a security tool that skips its
# own checksum is not a security tool.
#
# Usage: install.sh [version] [dest]
#   version  e.g. v0.1.0, or empty to build from source
#   dest     install prefix (binary goes to "$dest/bin/skillguard")
#
# Env:
#   SKILLGUARD_REPO          default lxbworld/SkillGuard
#   SKILLGUARD_RELEASE_BASE  default https://github.com/$REPO/releases/download
#                            (override to test against a local directory)

set -euo pipefail

version="${1:-}"
dest="${2:-${RUNNER_TEMP:-/tmp}/skillguard}"
repo="${SKILLGUARD_REPO:-lxbworld/SkillGuard}"
base="${SKILLGUARD_RELEASE_BASE:-https://github.com/${repo}/releases/download}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The repository root is the nearest ancestor with a Cargo.toml. Walking up
# rather than counting `..` keeps this correct wherever the action lives.
src_root="${here}"
while [ "${src_root}" != "/" ] && [ ! -f "${src_root}/Cargo.toml" ]; do
  src_root="$(dirname "${src_root}")"
done

log() { printf '%s\n' "$*" >&2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    log "no sha256 tool found (sha256sum or shasum)"
    return 1
  fi
}

asset_for_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "${os}-${arch}" in
    linux-x86_64) echo "skillguard-linux-x86_64.tar.gz" ;;
    linux-aarch64 | linux-arm64) echo "skillguard-linux-aarch64.tar.gz" ;;
    darwin-x86_64) echo "skillguard-macos-x86_64.tar.gz" ;;
    darwin-arm64) echo "skillguard-macos-aarch64.tar.gz" ;;
    mingw* | msys* | cygwin*) echo "skillguard-windows-x86_64.tar.gz" ;;
    *) echo "" ;;
  esac
}

install_from_release() {
  local asset url tmp expected actual
  asset="$(asset_for_platform)"
  if [ -z "${asset}" ]; then
    log "no prebuilt asset for $(uname -s)/$(uname -m); falling back to source build"
    return 2
  fi

  tmp="$(mktemp -d)"
  url="${base}/${version}/${asset}"
  log "downloading ${url}"
  if ! curl -fsSL "${url}" -o "${tmp}/${asset}"; then
    log "download failed; falling back to source build"
    return 2
  fi
  if ! curl -fsSL "${url}.sha256" -o "${tmp}/${asset}.sha256"; then
    log "checksum file missing for ${asset}; refusing to install an unverified binary"
    return 1
  fi

  expected="$(awk '{print $1}' "${tmp}/${asset}.sha256")"
  actual="$(sha256_of "${tmp}/${asset}")"
  if [ "${expected}" != "${actual}" ]; then
    log "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
    log "refusing to install; a tampered artifact is not a fallback case"
    return 1
  fi
  log "checksum verified: ${actual}"

  tar -xzf "${tmp}/${asset}" -C "${tmp}"
  bin="skillguard"
  if [ -f "${tmp}/skillguard.exe" ]; then
    bin="skillguard.exe"
  fi
  install -d "${dest}/bin"
  cp "${tmp}/${bin}" "${dest}/bin/${bin}"
  chmod +x "${dest}/bin/${bin}" 2>/dev/null || true
  rm -rf "${tmp}"
}

install_from_source() {
  if ! command -v cargo >/dev/null 2>&1; then
    log "cargo is not available and no prebuilt release could be downloaded"
    return 1
  fi
  log "building SkillGuard from ${src_root}"
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${dest}/target}" \
    cargo install --path "${src_root}" --locked --root "${dest}" >&2
}

# A version means "use the prebuilt asset". Return codes distinguish "none
# available" (2, fall back to source) from "present but failed verification"
# (1, refuse): a checksum mismatch must never be quietly papered over by a
# source build.
if [ -z "${version}" ]; then
  install_from_source
else
  rc=0
  install_from_release || rc=$?
  case "${rc}" in
    0) ;;
    2)
      log "no usable prebuilt asset for ${version}; building from source"
      install_from_source
      ;;
    *)
      log "release verification failed for ${version}; refusing to install"
      exit 1
      ;;
  esac
fi

"${dest}/bin/skillguard" --version
log "installed to ${dest}/bin/skillguard"
