#!/usr/bin/env bash
#
# pre-commit entry point.
#
# A changed file inside a skill means that skill must be re-scanned, even if
# `SKILL.md` itself did not change: a skill is `SKILL.md` *plus* its scripts, and
# a malicious change usually lands in a script. pre-commit hands us the changed
# files, so this maps each one to the nearest ancestor that contains a
# `SKILL.md` and scans every such directory once.
#
# Not finding a skill is not an error: the hook is also installed in repositories
# that only contain skills in some directories, or none at all.

set -euo pipefail

dirs=()
for f in "$@"; do
  [ -f "$f" ] || continue
  d="$(dirname "$f")"
  while [ "$d" != "." ] && [ "$d" != "/" ] && [ ! -f "$d/SKILL.md" ]; do
    next="$(dirname "$d")"
    [ "$next" = "$d" ] && break
    d="$next"
  done
  if [ -f "$d/SKILL.md" ]; then
    dirs+=("$d")
  fi
done

if [ "${#dirs[@]}" -eq 0 ]; then
  echo "skillguard: no Agent Skill among the changed files; nothing to scan"
  exit 0
fi

# Deduplicate while preserving order (bash 3.2 compatible: no assoc arrays).
seen=""
unique=()
for d in "${dirs[@]}"; do
  if printf '%s\n' "$seen" | grep -qxF "$d"; then
    continue
  fi
  seen="${seen}${d}"$'\n'
  unique+=("$d")
done

echo "skillguard: scanning ${#unique[@]} skill(s) at ${SKILLGUARD_FAIL_ON:-high} or above"
exec skillguard scan "${unique[@]}" --fail-on "${SKILLGUARD_FAIL_ON:-high}"
