#!/usr/bin/env bash
#
# One-command installer for SkillGuard.
#
#   curl -fsSL https://raw.githubusercontent.com/lxbworld/SkillGuard/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/lxbworld/SkillGuard/main/install.sh | bash -s -- v0.1.1
#
# The real work lives in action/install.sh, because the GitHub Action and this
# installer must behave identically: download the prebuilt asset for this
# platform, verify its SHA-256, and refuse to install on a mismatch.
#
# This file is the front door, and it has two shapes:
#   * run from a checkout (`bash install.sh`)          -> use the local copy;
#   * piped to bash (`curl … | bash`), where there is no local copy and
#     `${BASH_SOURCE[0]}` is unset                       -> fetch the real
#     installer from the same ref and run it.
#
# The second shape is the one the README documents, and it was broken until
# issue #18: a piped script has no directory, so delegating to a relative path
# failed with `BASH_SOURCE[0]: unbound variable`.

set -euo pipefail

version="${1:-}"
repo="${SKILLGUARD_REPO:-lxbworld/SkillGuard}"

# Default install prefix. action/install.sh defaults to a temp directory, which is
# right for a CI job and wrong for a first-time user: the binary lands somewhere
# that is deleted on reboot and is not on PATH. The front door installs into
# ~/.local (binary at ~/.local/bin/skillguard), which is on PATH on most systems,
# and says so when it is not.
if [ -z "${2:-}" ]; then
  set -- "${version}" "${HOME:-/tmp}/.local"
fi

# `${BASH_SOURCE[0]}` is unset when the script arrives on stdin, and `set -u`
# turns that into an error rather than an empty string.
here="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"

if [ -n "${here}" ] && [ -f "${here}/action/install.sh" ]; then
  exec "${here}/action/install.sh" "$@"
fi


# Piped: fetch the installer for the requested version — the tag if one was
# given, `main` otherwise — so the script that runs is the one from that release.
raw="${SKILLGUARD_RAW_BASE:-https://raw.githubusercontent.com/${repo}}"
ref="${version:-main}"
url="${raw}/${ref}/action/install.sh"

if ! command -v curl >/dev/null 2>&1; then
  printf 'install.sh: curl is required to fetch %s\n' "${url}" >&2
  exit 3
fi

tmp="$(mktemp)" || exit 3
trap 'rm -f "${tmp}"' EXIT
if ! curl -fsSL "${url}" -o "${tmp}"; then
  printf 'install.sh: could not fetch the installer from %s\n' "${url}" >&2
  exit 3
fi

# Not `exec`: the exit trap has to run, or the temporary installer leaks.
status=0
bash "${tmp}" "$@" || status=$?
if [ "${status}" -eq 0 ]; then
  case ":${PATH}:" in
    *":${HOME}/.local/bin:"*) ;;
    *)
      printf '\n%s\n' \
        "${HOME}/.local/bin is not on your PATH. Add it, then run: skillguard demo" >&2
      ;;
  esac
fi
exit "${status}"
