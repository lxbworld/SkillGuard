#!/usr/bin/env python3
"""Backfill `root_license` into an already-collected provenance sidecar.

`collect_github.py` records whether the source repository has a license at its
root. Rows collected before that field existed need it, because the corpus tree
is not a git checkout and the scanner therefore cannot see a repo-root license —
without it, `LICENSE_MISSING` over-reports (measured: 19 of 30 sampled flags had
a repo-root LICENSE).

One API call per unique repository. Idempotent: rows that already have the field
are left alone.

Usage: research/backfill_repo_license.py [tree]   (default research/raw)
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


def token() -> str:
    import os

    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    return subprocess.check_output(["gh", "auth", "token"], text=True).strip()


def api(path: str, tok: str) -> dict:
    out = subprocess.check_output(
        ["gh", "api", path, "-H", "Accept: application/vnd.github+json"],
        text=True,
        env={**__import__("os").environ, "GH_TOKEN": tok},
    )
    return json.loads(out)


def has_root_license(tree: dict) -> bool:
    for e in tree.get("tree", []):
        if e.get("type") != "blob" or "/" in e.get("path", ""):
            continue
        n = e["path"].lower()
        if n.startswith("license") or n.startswith("copying") or n == "notice":
            return True
    return False


def main() -> int:
    tree_root = Path(sys.argv[1] if len(sys.argv) > 1 else "research/raw")
    prov_path = tree_root / "_provenance.jsonl"
    rows = [json.loads(line) for line in prov_path.read_text().splitlines() if line.strip()]
    tok = token()

    by_repo: dict[str, list[dict]] = {}
    for r in rows:
        by_repo.setdefault(f"{r['repo']}@{r['commit']}", []).append(r)

    checked = 0
    for key, group in sorted(by_repo.items()):
        if all("root_license" in r for r in group):
            continue
        repo, commit = key.rsplit("@", 1)
        try:
            tree = api(f"/repos/{repo}/git/trees/{commit}", tok)
            lic = has_root_license(tree)
        except Exception as exc:  # a deleted or private repo is not fatal
            print(f"  {repo}: {exc}", file=sys.stderr)
            continue
        for r in group:
            r["root_license"] = lic
        checked += 1
        if checked % 50 == 0:
            print(f"  {checked} repos checked", file=sys.stderr)
        time.sleep(0.05)

    rows.sort(key=lambda r: r["path"])
    with prov_path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    missing = sum(1 for r in rows if "root_license" not in r)
    print(f"backfilled {checked} repos; {missing} rows still unknown", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
