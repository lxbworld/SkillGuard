#!/usr/bin/env python3
"""Extract a deterministic sample of findings with their source context.

The Phase 0 report publishes prevalence. A prevalence without a precision is not
a result (research/PROTOCOL.md §4.3), so the next step is to label a sample of
findings. This script does the mechanical half:

  findings JSONL + manifest + fetched tree
      -> a worksheet with, per finding, the evidence line and its neighbours

A human then fills in `verdict` (tp / fp) and the worksheet can be fed to
`skillguard corpus report --gold`.

This is *not* GOLD-v1. GOLD-v1 needs two independent annotators and a Cohen's
kappa >= 0.75; this is a single-annotator first pass, and the report must say so.
The sample is deterministic (hash order) so it can be repeated and re-labelled.

Usage: research/make_precision_sample.py [--per-rule N] [--out FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

TREE = Path("research/raw")
MANIFEST = Path("research/corpus-manifest.jsonl")
FINDINGS = Path("research/raw-findings.jsonl")
OUT = Path("research/gold/PILOT-precision.worksheet.jsonl")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--per-rule", type=int, default=12)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    path_of = {}
    for line in MANIFEST.read_text().splitlines():
        e = json.loads(line)
        path_of[e["source_id"]] = e["path"]

    findings = []
    for line in FINDINGS.read_text().splitlines():
        rec = json.loads(line)
        for f in rec.get("findings", []):
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

    out_rows = []
    for rule in sorted(by_rule):
        hits = sorted(
            by_rule[rule],
            key=lambda f: hashlib.sha256(
                f"{f['source_id']}|{f['file']}|{f['line']}".encode()
            ).hexdigest(),
        )[: args.per_rule]
        for f in hits:
            base = TREE / path_of.get(f["source_id"], "")
            target = base / f["file"]
            evidence = ""
            before = after = ""
            try:
                lines = target.read_text(errors="replace").splitlines()
                if 0 < f["line"] <= len(lines):
                    evidence = lines[f["line"] - 1].strip()[:200]
                    before = lines[f["line"] - 2].strip()[:120] if f["line"] > 1 else ""
                    after = (
                        lines[f["line"]].strip()[:120]
                        if f["line"] < len(lines)
                        else ""
                    )
            except OSError:
                evidence = "<file not in the fetched tree>"
            out_rows.append(
                {
                    "source_id": f["source_id"],
                    "rule": f["rule"],
                    "file": f["file"],
                    "line": f["line"],
                    "before": before,
                    "evidence": evidence,
                    "after": after,
                    "verdict": None,
                }
            )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for r in out_rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"{len(out_rows)} findings across {len(by_rule)} rules -> {out}")
    for rule in sorted(by_rule):
        print(f"  {len(by_rule[rule]):5d}  {rule}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
