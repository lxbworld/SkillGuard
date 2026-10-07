#!/usr/bin/env python3
"""Build the GOLD-v1 labelling worksheet.

Each row is one **finding**: a rule, the line it matched, and a little context.
An annotator judges `tp` (the rule is right) or `fp` (the rule is wrong). Two
annotators must label the same file independently, blind to each other; the
agreement between them is Cohen's kappa (`skillguard corpus agreement`).

The sample is deterministic (hash order over `source_id|file|line`), so the
same worksheet can be rebuilt and re-labelled — GOLD is versioned, never
retuned in place.

The evaluator does **not** need to know the rules; each row carries the rule's
own `claim`, so the judgment is "is this claim true of this line?".

Usage: research/build_gold.py [--per-rule N] [--out FILE]
Writes: research/gold/GOLD-v1.worksheet.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

TREE = Path("research/raw")
MANIFEST = Path("research/corpus-manifest.jsonl")
FINDINGS = Path("research/raw-findings.jsonl")
BIN = "target/release/skillguard"
OUT = Path("research/gold/GOLD-v1.worksheet.jsonl")


def rule_claims() -> dict[str, str]:
    """id -> the rule's own one-line claim, from the tool itself."""
    out = subprocess.check_output(
        [BIN, "scan", "tests/fixtures/corpus", "--list-rules", "--format", "json"],
        text=True,
    )
    return {r["id"]: r["message"] for r in json.loads(out)["rules"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--per-rule", type=int, default=8)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    claims = rule_claims()
    path_of = {
        json.loads(l)["source_id"]: json.loads(l)["path"]
        for l in MANIFEST.read_text().splitlines()
    }

    findings = []
    for line in FINDINGS.read_text().splitlines():
        rec = json.loads(line)
        # One row per rule per skill: a rule that fired on several lines of one
        # skill is one judgment, not five.
        seen: set[str] = set()
        for f in rec.get("findings", []):
            if f["rule"] in seen:
                continue
            seen.add(f["rule"])
            findings.append(
                {
                    "source_id": rec["source_id"],
                    "rule": f["rule"],
                    "file": f["file"],
                    "line": f["line"],
                }
            )

    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)

    rows = []
    for rule in sorted(by_rule):
        hits = sorted(
            by_rule[rule],
            key=lambda f: hashlib.sha256(
                f"{f['source_id']}|{f['file']}|{f['line']}".encode()
            ).hexdigest(),
        )[: args.per_rule]
        for f in hits:
            # A line-level judgment needs a real line. Skill-level rules
            # (`LICENSE_MISSING`, `MISMATCH_*`) are verified separately.
            if f["line"] <= 0:
                continue
            target = TREE / path_of.get(f["source_id"], "") / f["file"]
            try:
                lines = target.read_text(errors="replace").splitlines()
            except OSError:
                lines = []
            idx = f["line"] - 1
            if not (0 <= idx < len(lines) and lines[idx].strip()):
                idx = None
                for d in range(1, 5):
                    for j in (f["line"] - 1 - d, f["line"] - 1 + d):
                        if 0 <= j < len(lines) and lines[j].strip():
                            idx = j
                            break
                    if idx is not None:
                        break
            if idx is None:
                continue
            evidence = lines[idx].strip()[:300]
            before = lines[idx - 1].strip()[:160] if idx > 0 else ""
            after = lines[idx + 1].strip()[:160] if idx + 1 < len(lines) else ""
            rows.append(
                {
                    "source_id": f["source_id"],
                    "rule": f["rule"],
                    "claim": claims.get(rule, ""),
                    "file": f["file"],
                    "line": f["line"],
                    "before": before,
                    "evidence": evidence,
                    "after": after,
                }
            )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"{len(rows)} findings across {len(by_rule)} rules -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
