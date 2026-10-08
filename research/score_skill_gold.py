#!/usr/bin/env python3
"""Score the skill-level GOLD (`SKILL-v1`) against the scanner's findings.

A line-level GOLD cannot measure `PI_DESCRIPTION_MISMATCH`, because its claim is
about a whole skill. This reads the skill-level labels (annotators answered a
capability questionnaire per skill) and computes per-rule precision and recall,
per annotator and by consensus.

Usage: research/score_skill_gold.py
"""

from __future__ import annotations

import json
from pathlib import Path

WS = Path("research/gold/SKILL-v1.worksheet.jsonl")

# capability category -> the rules whose claim it decides
CATEGORY_RULES = {
    "network": ["NET_FETCH_CALL", "NET_HTTP_CLIENT", "NET_DOMAIN_LITERAL", "NET_DYNAMIC_URL"],
    "secrets": ["FS_SENSITIVE_PATH", "SECRET_ENV_DUMP", "SECRET_PATH_READ"],
    "shell": ["SHELL_EXEC", "SHELL_EVAL"],
    "injection": ["PI_INJECTION_OVERRIDE", "PI_CONCEALMENT", "PI_SYSTEM_IMPERSATION"],
    "exfiltration": ["PI_EXFIL_INSTRUCTION"],
    "obfuscation": ["OBFUSC_HOMOGLYPH", "OBFUSC_ZERO_WIDTH", "OBFUSC_BIDI_CONTROL"],
    "persistence": ["PERSIST_AGENT_CONFIG", "PERSIST_HOOK", "PERSIST_SHELL_RC", "PERSIST_CRON"],
    "understated": ["PI_DESCRIPTION_MISMATCH"],
}


def labels(tag: str) -> dict[tuple[str, str], bool]:
    out = {}
    p = Path(f"research/gold/SKILL-v1.annotator-{tag}.jsonl")
    for line in p.read_text().splitlines():
        o = json.loads(line)
        out[(o["source_id"], o["rule"].removeprefix("cat:"))] = o["verdict"] == "tp"
    return out


def score(name: str, lab: dict[tuple[str, str], bool]) -> None:
    ws = [json.loads(l) for l in WS.read_text().splitlines()]
    print(f"\n{name}")
    print(f"  {'rule':26s} {'tp':>3} {'fp':>3} {'fn':>3}  {'precision':>9} {'recall':>7}")
    for cat, rules in CATEGORY_RULES.items():
        for rule in rules:
            tp = fp = fn = 0
            for w in ws:
                sid = w["source_id"]
                key = (sid, cat)
                if key not in lab:
                    continue
                fired = rule in w["fired"]
                und = lab[key]
                if fired and und:
                    tp += 1
                elif fired and not und:
                    fp += 1
                elif not fired and und:
                    fn += 1
            if tp + fp + fn == 0:
                continue
            p = f"{tp / (tp + fp):.1%}" if tp + fp else "n/a"
            r = f"{tp / (tp + fn):.1%}" if tp + fn else "n/a"
            print(f"  {rule:26s} {tp:3d} {fp:3d} {fn:3d}  {p:>9} {r:>7}")


def main() -> int:
    a, b = labels("sga"), labels("sgb")
    score("annotator A", a)
    score("annotator B", b)
    consensus = {
        k: a[k] for k in a if k in b and a[k] == b[k]
    }
    score(f"consensus ({len(consensus)} of {len(a)} items agreed)", consensus)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
