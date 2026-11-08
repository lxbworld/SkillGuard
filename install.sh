#!/usr/bin/env bash
#
# One-command installer for SkillGuard.
#
#   curl -fsSL https://raw.githubusercontent.com/lxbworld/SkillGuard/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/lxbworld/SkillGuard/main/install.sh | bash -s -- v0.1.1
#
# The real work lives in action/install.sh, because the GitHub Action and this
# installer must behave identically: download the prebuilt asset for this
# platform, verify its SHA-256, and refuse to install on a mismatch. This file
# only exists so a first-time user does not have to know where that lives.
#
# With no version, it builds from source when run from a checkout; with a
# version, it always prefers the verified prebuilt binary.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${here}/action/install.sh" "$@"
