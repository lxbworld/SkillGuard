#!/usr/bin/env python3
"""Score a rule-shaped skill-level GOLD (SKILL-v2).

`SKILL-v1` asked broad categories (`network`, `secrets`), which cannot measure a
rule's recall: the category is much wider than any one rule, so a skill that
reaches the network through `curl` counted as a miss for `NET_FETCH_CALL`, which
never claimed it. This asks each rule's own claim instead, so precision and
recall are both meaningful.

Usage: research/score_skill_gold2.py
"""

from __future__ import annotations

import json
from pathlib import Path

WS = Path("research/gold/SKILL-v1.worksheet.jsonl")
RULES = [
    "NET_FETCH_CALL",
    "NET_HTTP_CLIENT",
    "NET_DOMAIN_LITERAL",
    "FS_ABSOLUTE_PATH",
    "FS_HOME_ACCESS",
    "FS_PATH_ESCAPE",
    "FS_RECURSIVE_WALK",
    "SHELL_EXEC",
    "LICENSE_RESTRICTIVE",
    "PERSIST_AGENT_CONFIG",
]


def labels(tag: str) -> dict[tuple[str, str], bool]:
    out = {}
    p = Path(f"research/gold/SKILL-v2.annotator-{tag}.jsonl")
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        o = json.loads(line)
        out[(o["source_id"], o["rule"].removeprefix("cat:"))] = o["verdict"] == "tp"
    return out


def score(name: str, lab: dict[tuple[str, str], bool]) -> None:
    ws = [json.loads(l) for l in WS.read_text().splitlines()]
    print(f"\n{name}")
    print(f"  {'rule':24s} {'tp':>3} {'fp':>3} {'fn':>3}  {'precision':>9} {'recall':>7}")
    for rule in RULES:
        tp = fp = fn = 0
        for w in ws:
            sid = w["source_id"]
            if (sid, rule) not in lab:
                continue
            fired = rule in w["fired"]
            yes = lab[(sid, rule)]
            if fired and yes:
                tp += 1
            elif fired and not yes:
                fp += 1
            elif not fired and yes:
                fn += 1
        if tp + fp + fn == 0:
            continue
        p = f"{tp / (tp + fp):.1%}" if tp + fp else "n/a"
        r = f"{tp / (tp + fn):.1%}" if tp + fn else "n/a"
        print(f"  {rule:24s} {tp:3d} {fp:3d} {fn:3d}  {p:>9} {r:>7}")


def main() -> int:
    a, b = labels("sga2"), labels("sgb2")
    score("annotator A", a)
    score("annotator B", b)
    cons = {k: a[k] for k in a if k in b and a[k] == b[k]}
    score(f"consensus ({len(cons)} agreed)", cons)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
