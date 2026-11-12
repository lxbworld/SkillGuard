#!/usr/bin/env python3
"""Label a GOLD worksheet with one model session.

`research/GOLD.md` requires two independent annotators, blind to each other, over
a sample of findings, and Cohen's kappa (>= 0.75) before any precision figure is
published. This script is the annotator: it reads a worksheet produced by
`research/build_gold.py`, asks a model to judge each row, and writes the label
set that `skillguard corpus agreement` and `corpus report --gold` consume.

Blindness is structural, not a promise: one process per annotator, one worksheet,
no access to the other label file. Run it twice, into two files.

The model is called through the `pi` CLI with tools disabled, so it sees exactly
the row and nothing else — no repository, no rules, no other labels.

Usage:
  research/annotate_gold.py --worksheet research/gold/GOLD-v6.worksheet.jsonl \
      --out research/gold/GOLD-v6.annotator-a6.jsonl
  research/annotate_gold.py --worksheet ... --out ...annotator-b6.jsonl

Each row carries the rule's own `claim`, so the judgment is "is this claim true
of this line?", which nobody needs to know the rule set to answer.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

INSTRUCTION = """\
You are the annotator for a security scanner's published precision figure.

Each row is one finding. `claim` is the rule's own one-line statement about what
it detected. `evidence` is the source line it matched, with `before`/`after` as
the surrounding context. Judge the claim against the line:

- "tp" — the line really is an instance of what the claim says.
- "fp" — it is not.

Judge only the claim, not whether the rule is useful or well written.
- If the claim describes an ACTION or an ACCESS (reads, writes, contacts, runs,
  installs), then a mention is not an instance: a comment, a docstring, a help
  message, a test fixture, a variable name, an import, or text that merely names
  the thing is "fp".
- A `SKILL.md` body is the exception and it matters more than anything else
  here: that text *is* the instruction an agent follows, so a command in it is
  an instance, not a mention. A fenced code block in a skill's own instructions
  is the command the agent is told to run. Only a `SKILL.md` passage that talks
  *about* the command ("never run `curl | bash`", "attacks use `rm -rf /`") is a
  mention.
- Other Markdown (a `README`, a `docs/*.md`, a reference file) is documentation:
  an example there is a mention, unless the file is telling the agent what to do.
- If the claim describes PRESENCE (a hardcoded credential, a control character,
  an embedded remote image, a licence term), then presence in the line is
  enough, including inside a comment or documentation.
- "The home directory is referenced" is satisfied by any `~/`; "the home
  directory is accessed" is not.
Be strict and literal. When the line is a false example of the claim, say "fp".

Reply with one JSON array and nothing else, one object per row in input order:
[{"i": 0, "verdict": "tp", "why": "<12 words max>"}, ...]
"""


def run_batch(rows: list[dict], provider: str, model: str, attempt: int = 0) -> list[dict]:
    payload = json.dumps(
        [
            {
                "i": i,
                "claim": r.get("claim", ""),
                "evidence": r.get("evidence", ""),
                "before": r.get("before", ""),
                "after": r.get("after", ""),
            }
            for i, r in enumerate(rows)
        ],
        indent=None,
    )
    prompt = f"{INSTRUCTION}\nRows:\n{payload}\n"
    out = subprocess.run(
        [
            "pi",
            "--provider",
            provider,
            "--model",
            model,
            "--no-session",
            "--no-tools",
            "--mode",
            "text",
            "-p",
            prompt,
        ],
        capture_output=True,
        text=True,
        timeout=900,
    )
    body = out.stdout.strip()
    start, end = body.find("["), body.rfind("]")
    if start < 0 or end < start:
        raise ValueError(f"no JSON array in reply: {body[:400]!r} {out.stderr[:200]!r}")
    labels = json.loads(body[start : end + 1])
    if len(labels) != len(rows):
        raise ValueError(f"expected {len(rows)} labels, got {len(labels)}")
    return labels


def annotate(rows: list[dict], provider: str, model: str, batch: int) -> list[dict]:
    labels: list[dict] = []
    for at in range(0, len(rows), batch):
        chunk = rows[at : at + batch]
        for attempt in range(4):
            try:
                got = run_batch(chunk, provider, model)
                break
            except (ValueError, subprocess.TimeoutExpired) as e:
                print(f"  batch {at // batch} attempt {attempt + 1} failed: {e}", file=sys.stderr)
                if attempt == 3:
                    raise
        for j, label in enumerate(got):
            verdict = str(label.get("verdict", "")).strip().lower()
            if verdict not in ("tp", "fp"):
                raise ValueError(f"bad verdict {label!r}")
            row = chunk[j]
            labels.append(
                {
                    "source_id": row["source_id"],
                    "rule": row["rule"],
                    "verdict": verdict,
                }
            )
        print(f"  {len(labels)}/{len(rows)} labelled", file=sys.stderr)
    return labels


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worksheet", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--provider", default="command-code")
    ap.add_argument("--model", default="deepseek/deepseek-v4.1-flash")
    ap.add_argument("--batch", type=int, default=25)
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.worksheet).read_text().splitlines() if l.strip()]
    labels = annotate(rows, args.provider, args.model, args.batch)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for r in labels:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    tp = sum(1 for r in labels if r["verdict"] == "tp")
    print(f"{len(labels)} labels ({tp} tp, {len(labels) - tp} fp) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
