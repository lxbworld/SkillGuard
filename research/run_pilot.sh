#!/usr/bin/env bash
#
# Phase 0 pilot: run the corpus pipeline end to end on a real GitHub sample.
#
# This is a PILOT, not the pre-registered N=100,000 stratified study:
#   * the sample is an opportunistic GitHub code-search slice, not the
#     stratified draw in research/PROTOCOL.md §5;
#   * the annotators are two model sessions, not the two humans that
#     PROTOCOL.md G3 asks for, so the precision column is a model-labelled pass.
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
GOLD="research/gold/GOLD-v6.jsonl"
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
> `research/PROTOCOL.md` §5, and the precision column comes from model
> annotators rather than the two humans `research/PROTOCOL.md` G3 asks for. Read
> the numbers as a first signal and a proof that the pipeline runs on real data,
> not as the study's result.
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
> ## GOLD-v6
>
> The precision column below is measured against `research/gold/GOLD-v6.jsonl`:
> 209 line-level findings across 36 rules at `SCAN_LOGIC_REVISION = 50`, eight
> per rule in hash order, one judgment per skill and rule. Two independent
> sessions of `command-code/deepseek-v4.1-flash` labelled them blind to each
> other — **no human annotated this set**, and neither annotator wrote the rules.
> Cohen's kappa is **0.827** over the 209 scored rows (gate 0.75); the 17
> disagreements were adjudicated by a third session shown both verdicts, and
> every rule figure below is per rule, never micro-averaged.
>
> Neither annotator being human is the limitation, not a detail. Two sessions of
> one model share blind spots, so they agree on a wrong label as readily as on a
> right one, and the kappa above is a test–retest figure rather than inter-human
> agreement. `research/GOLD.md` says what that costs and what would fix it.
>
> **13 of 36 rules reach the 0.85 precision gate**, and ten of them are at 100%:
> `FS_PATH_ESCAPE`, `NET_HTTP_CLIENT`, `FS_SENSITIVE_PATH`, `FS_MODE_UNRESOLVED`,
> `NET_DYNAMIC_URL`, `LICENSE_RESTRICTIVE`, `FS_HOME_ACCESS`,
> `SECRET_PROVIDER_TOKEN`, `DL_CHAIN_FETCH_EXECUTE` and `DEP_UNPINNED_SCRIPT`.
> `FS_RECURSIVE_WALK`, `NET_FETCH_CALL` and `SECRET_ENV_DUMP` are at 7/8.
> (GOLD-v5 measured `FS_PATH_ESCAPE` and `NET_HTTP_CLIENT` at 87.5%.)
>
> Where they did not: `SHELL_PRIVILEGE_ESCALATION` 0/8, `PERSIST_HOOK` 0/6,
> `PERSIST_SHELL_RC` 0/4, `PI_INJECTION_OVERRIDE` 0/8 and `DL_PIPE_TO_SHELL` 0/2
> were false positives on every sampled finding. The `PI_*` family is where
> GOLD-v5 left it — the corpus is full of security *training* material that
> discusses injection, and a phrase rule cannot tell "issues this" from
> "documents this", which is why they are `Info`: a false `Critical` is worse
> than no finding. They still force a human to read the line; they no longer
> block a gate. Treat every prevalence figure below as an upper bound.
>
> Two **skill-level** rules are excluded rather than measured: `PARSE_FAILED` and
> `PI_DESCRIPTION_MISMATCH` report on the skill as a whole and carry no evidence
> line, so a line-level judgment about them is a judgment about the frontmatter
> delimiter. GOLD-v5 sampled them anyway and published a 0% that measured the
> sampling, not the rule; `research/build_gold.py` now refuses to sample them.
> They need a skill-level questionnaire like `SKILL-v1` below.
>
> (GOLD-v1..v5 stay in `research/gold/`. Versions are not directly comparable:
> both the raters and the rule set change.)
>
> A separate **skill-level** pass (`SKILL-v1`, 30 skills, questionnaire, no rule
> output) measured `PI_DESCRIPTION_MISMATCH` directly: precision **17.6% / 35.3%**,
> and the underlying "is the description understated?" judgment has **κ 0.359** —
> the annotators cannot agree on it. Breaking it down by branch: the **network
> and shell branches scored 0/6 correct**, the credential branch 1-2/4. The two
> dead branches have been **removed**; what remains is the checkable case (the
> code reads credentials and the description mentions neither credentials nor
> security). Prevalence fell 10.7% -> 6.4%. See `research/GOLD.md`.
>
> The `PI_*` heuristics that remain are measured above, and every one of them is
> below the gate. They are published because the evidence line is still worth a
> human read, and their prevalence figures are upper bounds like every other row.

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
