#!/usr/bin/env bash
#
# Phase 0 pilot: run the corpus pipeline end to end on a real GitHub sample.
#
# This is a PILOT, not the pre-registered N=100,000 stratified study:
#   * the sample is an opportunistic GitHub code-search slice, not the
#     stratified draw in research/PROTOCOL.md §5;
#   * there is no GOLD label set, so no precision or recall is reported.
# It exists to prove the pipeline on real data and to produce a first, honest
# signal on H6 (do skills declare permissions at all?).
#
# Usage: research/run_pilot.sh [limit]     (default 400 skills)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# `cargo` is not always on the default PATH (e.g. a minimal shell).
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

LIMIT="${1:-400}"
TREE="research/raw"
MANIFEST="research/corpus-manifest.jsonl"
FINDINGS="research/raw-findings.jsonl"

echo "== 1/6 build =="
cargo build --release --quiet

echo "== 2/6 collect (limit $LIMIT) =="
if [ "${SKIP_COLLECT:-0}" = "1" ]; then
  echo "  SKIP_COLLECT=1: reusing $TREE"
else
  python3 research/collect_github.py --limit "$LIMIT" --tree "$TREE"
fi

echo "== 3/6 index (digests + strata) =="
target/release/skillguard corpus index "$TREE" --layer L3 --out /tmp/sg-pilot-index.jsonl

echo "== 4/6 join GitHub provenance (repo + pinned commit) =="
python3 - "$TREE/_provenance.jsonl" /tmp/sg-pilot-index.jsonl "$MANIFEST" <<'PY'
import json, sys
prov_path, index_path, out_path = sys.argv[1:4]
prov = {}
with open(prov_path) as fh:
    for line in fh:
        r = json.loads(line)
        prov[r["path"]] = r
rows = []
with open(index_path) as fh:
    for line in fh:
        e = json.loads(line)
        p = prov.get(e["path"])
        if p:
            suffix = f"/{p['skill_dir']}" if p["skill_dir"] else ""
            e["source_id"] = f"github:{p['repo']}@{p['commit']}{suffix}"
            e["commit"] = p["commit"]
            if "root_license" in p:
                e["repo_license"] = p["root_license"]
        rows.append(e)
rows.sort(key=lambda r: r["source_id"])
with open(out_path, "w") as fh:
    for e in rows:
        fh.write(json.dumps(e, sort_keys=True) + "\n")
print(f"  {len(rows)} manifest entries -> {out_path}", file=sys.stderr)
PY

echo "== 5/6 scan (offline, cached) =="
target/release/skillguard corpus scan \
  --manifest "$MANIFEST" --tree "$TREE" \
  --out "$FINDINGS" --cache research/.corpus-cache.json

echo "== 6/6 report + reproduce =="
target/release/skillguard corpus report --findings "$FINDINGS" --out /tmp/sg-pilot-body.md

{
  cat <<'HEADER'
# SkillGuard Phase 0 corpus report

> **This is a pilot, not the pre-registered study.** The sample is an
> opportunistic GitHub code-search slice, not the stratified N=100,000 draw in
> `research/PROTOCOL.md` §5, and there is no GOLD label set yet, so the report
> contains **no precision or recall figure**. Read the numbers as a first signal
> and a proof that the pipeline runs on real data, not as the study's result.
>
> The `LICENSE_MISSING` figure is corrected for repository-root licenses: a
> skill vendored in a repository inherits that repository's license, and the
> corpus tree is not a git checkout, so the collector records the repo-root
> license and `corpus scan` honours it. Before the correction this rule read
> 87.2%; on a 30-skill sample, 19 of 30 flagged skills (63%) had a repo-root
> LICENSE, i.e. were false positives.

HEADER
  echo "## Collection"
  echo
  echo '```json'
  cat research/raw/_collection.json
  echo '```'
  echo
  # Skip the generated title line (the header above already has one).
  tail -n +3 /tmp/sg-pilot-body.md
} > docs/CORPUS_REPORT.md
echo "  wrote docs/CORPUS_REPORT.md"

target/release/skillguard corpus reproduce --manifest "$MANIFEST" --tree "$TREE"
