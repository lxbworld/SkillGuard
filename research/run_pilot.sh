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

# Index provenance by repository directory (the first two tree-relative path
# segments, `owner/name`). An exact path lookup is not enough: GitHub search
# surfaces one SKILL.md per hit, but the walker finds every nested SKILL.md in
# the fetched tree, and the nested ones have no provenance row of their own.
def repo_dir(path):
    return "/".join(path.split("/")[:2])

by_repo = {}
with open(prov_path) as fh:
    for line in fh:
        r = json.loads(line)
        rd = repo_dir(r["path"])
        prev = by_repo.get(rd)
        # Prefer a row that carries the repository-root license.
        if prev is None or ("root_license" in r and "root_license" not in prev):
            by_repo[rd] = r

rows, skipped = [], 0
with open(index_path) as fh:
    for line in fh:
        e = json.loads(line)
        rd = repo_dir(e["path"])
        p = by_repo.get(rd)
        if p is None:
            # No fetched repository contains this path: drop it rather than
            # attribute it to whatever repository happens to enclose the tree.
            skipped += 1
            continue
        rel = e["path"][len(rd):].lstrip("/")
        e["source_id"] = f"github:{p['repo']}@{p['commit']}" + (f"/{rel}" if rel else "")
        e["commit"] = p["commit"]
        e["repo_license"] = p.get("root_license")
        rows.append(e)
rows.sort(key=lambda r: r["source_id"])
with open(out_path, "w") as fh:
    for e in rows:
        fh.write(json.dumps(e, sort_keys=True) + "\n")
print(f"  {len(rows)} manifest entries ({skipped} unattributed skipped) -> {out_path}", file=sys.stderr)
PY

echo "== 5/6 scan (offline, cached) =="
target/release/skillguard corpus scan \
  --manifest "$MANIFEST" --tree "$TREE" \
  --out "$FINDINGS" --cache research/.corpus-cache.json

echo "== 6/6 report + reproduce =="
GOLD="research/gold/GOLD-v4.jsonl"
if [ -f "$GOLD" ]; then
  target/release/skillguard corpus report --findings "$FINDINGS" --gold "$GOLD" --out /tmp/sg-pilot-body.md
else
  target/release/skillguard corpus report --findings "$FINDINGS" --out /tmp/sg-pilot-body.md
fi

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
> LICENSE. A second error was attribution: GitHub search surfaces one
> `SKILL.md` per hit, but the walker finds every nested `SKILL.md` in the
> fetched tree, and nested skills had no provenance row — they were credited to
> whatever repository enclosed the tree (SkillGuard) and lost their own
> repository's license. The join now matches provenance by repository, so all
> every row carries its true repository and repository-root license.
>
> A precision pass over the first real corpus also corrected several heuristics
> that fired on ordinary text and file formats: lookalike characters in
> legitimate non-Latin prose, npm/pip/cargo integrity hashes, shields.io badges,
> the word "silently" in documentation, `regex.exec(`, file extensions that look
> like TLDs (`.zip`, `.mov`), XML namespaces, English-only keyword lists that
> flagged every non-English `PI_DESCRIPTION_MISMATCH`, and unstemmed verbs
> (`execution` did not match `execute`). Each fix is a regression test.
>
> ## GOLD-v4
>
> The precision column below is measured against `research/gold/GOLD-v4.jsonl`:
> 151 line-level findings, judged `tp`/`fp` by **two independent sessions** of
> `opencode-go/deepseek-v4.1-flash` (no human, and not the rule author). Cohen's
> kappa is **0.907**.
>
> This round fixed the last four rules' substring matching. `FS_ABSOLUTE_PATH`
> matched `/dev/` inside `/dev/null`; `FS_SENSITIVE_PATH` matched `read` inside
> `README` and `Readonly`; `DL_BASE64_BLOB` matched long lowercase paths; and a
> `# ...` after code was not treated as a comment. `FS_ABSOLUTE_PATH` rose
> `25% -> 50%`, `PERSIST_HOOK` `12.5% -> 66.7%`, and `DL_BASE64_BLOB` left the
> table.
>
> `FS_HOME_ACCESS` reads 100%, but that is a **tautology**: its claim is only
> that the home directory is "referenced", which any `~/` mention satisfies, and
> the two annotators disagreed on six of its eight items. The claim must be
> reworded to "accessed" before the number means anything. Treat every
> prevalence figure below as an upper bound.
>
> (GOLD-v1..v3 are kept in `research/gold/`. Versions are not directly
> comparable: both the raters and the rule set change.)
>
> A separate **skill-level** pass (`SKILL-v1`, 30 skills, questionnaire, no rule
> output) measured `PI_DESCRIPTION_MISMATCH` directly: precision **17.6% / 35.3%**
> across two annotators, and the underlying "is the description understated?"
> judgment has **κ 0.359** — the annotators cannot agree on it. That rule should
> not be published with a precision; its 7.4% prevalence is not a result. See
> `research/GOLD.md`.
>
> The remaining `PI_*` heuristics are **unmeasured upper bounds**. A
> single-annotator read-through is not `GOLD` (research/GOLD.md) and the report
> publishes no precision until two independent annotators agree (kappa >= 0.75).

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
