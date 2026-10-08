#!/usr/bin/env python3
"""Build a **skill-level** GOLD worksheet.

A line-level finding sample cannot measure `PI_DESCRIPTION_MISMATCH`: the claim
is about a whole skill ("the declared description does not match observed
behaviour"), and the scanner's own evidence line is the frontmatter delimiter.

Here an annotator reads a whole skill — normalized text, line numbers, **no rule
output** (`skillguard inspect --labeling`) — and answers a fixed questionnaire.
Rule precision is then derived: of the skills where a rule fired, how many did
the annotator say the corresponding capability applies?

Usage: research/build_skill_gold.py [--n N] [--out FILE]
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
OUT = Path("research/gold/SKILL-v1.worksheet.jsonl")
MAX_LINES = 260


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    path_of = {
        json.loads(l)["source_id"]: json.loads(l)["path"]
        for l in MANIFEST.read_text().splitlines()
    }
    rules_of: dict[str, set[str]] = {}
    for line in FINDINGS.read_text().splitlines():
        rec = json.loads(line)
        rules_of[rec["source_id"]] = {f["rule"] for f in rec.get("findings", [])}

    # Cover the rules that need a skill-level judgment, plus quiet skills.
    interesting = {
        "PI_DESCRIPTION_MISMATCH",
        "PI_INJECTION_OVERRIDE",
        "PI_CONCEALMENT",
        "PI_EXFIL_INSTRUCTION",
        "NET_FETCH_CALL",
        "SHELL_EXEC",
        "PERSIST_AGENT_CONFIG",
    }
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()
    flagged = sorted(
        (s for s, rs in rules_of.items() if rs & interesting), key=h
    )[: args.n * 2 // 3]
    quiet = sorted((s for s, rs in rules_of.items() if not rs), key=h)[
        : args.n - len(flagged)
    ]
    chosen = sorted(set(flagged) | set(quiet), key=h)[: args.n]

    rows = []
    for sid in chosen:
        base = TREE / path_of.get(sid, "")
        out = subprocess.run(
            [BIN, "inspect", str(base), "--labeling"],
            capture_output=True,
            text=True,
        )
        lines = [
            l
            for l in out.stdout.splitlines()
            if not l.startswith("  SkillGuard") and not l.startswith("  ==")
        ]
        if len(lines) > MAX_LINES:
            lines = lines[:MAX_LINES] + ["... (truncated)"]
        rows.append(
            {
                "source_id": sid,
                "text": "\n".join(lines),
                "fired": sorted(rules_of.get(sid, set())),
            }
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"{len(rows)} skills -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
