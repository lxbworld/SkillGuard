#!/usr/bin/env python3
"""Collect an L3 (GitHub) Agent-Skill corpus for the Phase 0 study.

`skillguard` itself has no HTTP client, on purpose: the architecture forbids a
network dependency in the scanner. Collection is therefore a separate, explicit
step, and this script is that step. It speaks the GitHub REST API, pins every
skill to a full 40-hex commit, and writes a tree that `skillguard corpus scan`
can read offline.

What it does, per skill:

1. `GET /search/code?q=filename:SKILL.md` to sample skills (search is rate
   limited to 10 requests/minute, so this is the slow part).
2. Resolve the repository's default-branch HEAD to a full commit SHA. Branches,
   tags and short SHAs are never used, because a corpus pinned to a moving ref
   cannot be reproduced (research/PROTOCOL.md).
3. `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1` once per repository
   (cached) to enumerate the skill directory.
4. Fetch each file from `raw.githubusercontent.com` at that exact commit. Raw
   does not count against the API rate limit. The executable bit comes from the
   tree entry's mode, because `sgdir-v1` hashes it.

The bytes land under `--tree` (default `research/raw/`), and a sidecar
`_provenance.jsonl` maps each skill path to its repository and commit. Run
`skillguard corpus index` on the tree afterwards to compute digests and strata,
then join the provenance in. `research/run_pilot.sh` does the whole sequence.

Ethics: this only reads public repositories at a low rate, stores path + commit
+ digest, and never executes anything it downloads. See research/DISCLOSURE.md.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
USER_AGENT = "SkillGuard-corpus-pilot (https://github.com/lxbworld/SkillGuard)"

# A skill larger than this is skipped and recorded, not truncated: truncating
# would silently change the digest. Real skills are a few kilobytes; the large
# ones are "the whole repository is the skill" monorepos, which are a different
# population and are reported as skipped rather than silently included.
MAX_SKILL_BYTES = 1536 * 1024
MAX_SKILL_FILES = 80

# Raw fetches are independent, so they run concurrently. Politeness is kept by
# the small pool and the low overall rate; raw.githubusercontent.com is a CDN
# and does not count against the API limit.
RAW_WORKERS = 8

# Never sample ourselves: our test fixtures are not ecosystem data.
EXCLUDE_REPOS = {"lxbworld/SkillGuard"}

# These directory names are excluded from `sgdir-v1` by `hash::digest_dir`, so a
# faithful manifest must not include them either. Skipping them here keeps the
# fetched tree's digest equal to a real checkout's, and avoids downloading
# vendored trees for no reason.
EXCLUDED_SEGMENTS = {".git", "node_modules", "__pycache__", ".venv", "target"}


def is_included(path: str) -> bool:
    return not any(seg in EXCLUDED_SEGMENTS for seg in path.split("/"))


def token() -> str:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        return subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    except Exception as exc:  # pragma: no cover - environment dependent
        sys.exit(f"no GitHub token: set GITHUB_TOKEN or run `gh auth login` ({exc})")


class Client:
    """A tiny, rate-limit-aware GitHub API client."""

    def __init__(self, tok: str, verbose: bool = False) -> None:
        self.tok = tok
        self.verbose = verbose
        self.calls = 0

    def get_json(self, path: str) -> dict:
        url = path if path.startswith("http") else f"{API}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.tok}",
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
            },
        )
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self.calls += 1
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    # Rate limited: honour the reset header, then retry.
                    reset = int(exc.headers.get("X-RateLimit-Reset", "0"))
                    wait = max(5, reset - int(time.time()) + 2) if reset else 60
                    if wait > 900:
                        sys.exit(f"rate limited for {wait}s; rerun later")
                    if self.verbose:
                        print(f"    rate limited, sleeping {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                if exc.code == 404:
                    raise
                raise
        raise RuntimeError(f"gave up on {url}")

    def get_raw(self, owner: str, repo: str, commit: str, path: str) -> bytes | None:
        url = f"{RAW}/{owner}/{repo}/{commit}/{urllib.parse.quote(path)}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    time.sleep(5 * (attempt + 1))
                    continue
                if exc.code == 404:
                    return None
                raise
            except urllib.error.URLError:
                time.sleep(3 * (attempt + 1))
        return None


def search_skills(client: Client, query: str, want: int) -> list[dict]:
    """Page through code search, returning (repo, skill_dir) candidates."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    page = 1
    while len(out) < want and page <= 10:
        path = f"/search/code?q={urllib.parse.quote(query)}&per_page=100&page={page}"
        data = client.get_json(path)
        items = data.get("items", [])
        if not items:
            break
        for it in items:
            repo = it.get("repository", {}).get("full_name", "")
            p = it.get("path", "")
            if not repo or not p.lower().endswith("skill.md"):
                continue
            if repo in EXCLUDE_REPOS:
                continue
            skill_dir = p[: -len("SKILL.md")].rstrip("/")
            if "node_modules/" in skill_dir or "/.git" in skill_dir:
                continue
            if not is_included(skill_dir + "/SKILL.md"):
                continue
            key = (repo, skill_dir)
            if key in seen:
                continue
            seen.add(key)
            out.append({"repo": repo, "skill_dir": skill_dir})
            if len(out) >= want:
                break
        page += 1
        # Code search: 10 requests/minute. Stay well under it.
        time.sleep(7)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=300, help="number of skills to collect")
    ap.add_argument("--tree", default="research/raw", help="where to write the fetched bytes")
    ap.add_argument(
        "--query",
        action="append",
        default=None,
        help="GitHub code-search query; repeatable to diversify the sample",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    queries = args.query or [
        "filename:SKILL.md",
        "filename:SKILL.md path:skills",
        "filename:SKILL.md path:.claude",
        "filename:SKILL.md path:agent",
    ]

    client = Client(token(), verbose=args.verbose)
    tree_root = Path(args.tree)
    tree_root.mkdir(parents=True, exist_ok=True)
    provenance_path = tree_root / "_provenance.jsonl"

    print(f"searching GitHub for up to {args.limit} skills ...", file=sys.stderr)
    per = max(1, args.limit // len(queries) + 1)
    candidates: list[dict] = []
    seen_keys: set[tuple[str, str]] = set()
    for q in queries:
        for cand in search_skills(client, q, per):
            key = (cand["repo"], cand["skill_dir"])
            if key not in seen_keys:
                seen_keys.add(key)
                candidates.append(cand)
        if len(candidates) >= args.limit:
            break
    candidates = candidates[: args.limit]
    print(f"  {len(candidates)} candidate skills from {len(queries)} queries", file=sys.stderr)

    repo_cache: dict[str, tuple[str, dict[str, dict]]] = {}
    provenance: list[dict] = []
    collected = skipped = failed = 0

    for i, cand in enumerate(candidates, 1):
        repo = cand["repo"]
        skill_dir = cand["skill_dir"]
        owner, name = repo.split("/", 1)

        try:
            if repo not in repo_cache:
                head = client.get_json(f"/repos/{repo}/commits/HEAD")["sha"]
                tree = client.get_json(f"/repos/{repo}/git/trees/{head}?recursive=1")
                entries = {
                    e["path"]: e
                    for e in tree.get("tree", [])
                    if e.get("type") == "blob" and e.get("mode") != "120000"
                }
                repo_cache[repo] = (head, entries)
            commit, entries = repo_cache[repo]
        except Exception as exc:
            failed += 1
            print(f"  [{i}] {repo} {skill_dir}: repo error {exc}", file=sys.stderr)
            continue

        prefix = f"{skill_dir}/" if skill_dir else ""
        members = [
            (p, e)
            for p, e in entries.items()
            if p.startswith(prefix) and is_included(p)
        ]
        total = sum(e.get("size", 0) for _, e in members)
        if not members:
            failed += 1
            continue
        if len(members) > MAX_SKILL_FILES or total > MAX_SKILL_BYTES:
            skipped += 1
            print(
                f"  [{i}] {repo}/{skill_dir}: skipped "
                f"({len(members)} files, {total} bytes)",
                file=sys.stderr,
            )
            continue

        dest = (tree_root / repo / skill_dir).resolve()
        if not str(dest).startswith(str(tree_root.resolve())):
            failed += 1
            continue

        paths = [p for p, _ in members]
        with concurrent.futures.ThreadPoolExecutor(max_workers=RAW_WORKERS) as pool:
            fetched = list(
                pool.map(lambda p: (p, client.get_raw(owner, name, commit, p)), paths)
            )
        if any(body is None for _, body in fetched):
            failed += 1
            continue
        for path, body in fetched:
            entry = entries[path]
            rel = path[len(prefix):] if prefix else path
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            if entry.get("mode") == "100755":
                target.chmod(0o755)

        provenance.append(
            {
                "path": str((tree_root / repo / skill_dir).relative_to(tree_root)),
                "repo": repo,
                "commit": commit,
                "skill_dir": skill_dir,
                "files": len(members),
                "bytes": total,
            }
        )
        collected += 1
        if i % 25 == 0 or i == len(candidates):
            print(
                f"  [{i}/{len(candidates)}] collected={collected} "
                f"skipped={skipped} failed={failed}",
                file=sys.stderr,
            )

    provenance.sort(key=lambda r: r["path"])
    with provenance_path.open("w") as fh:
        for row in provenance:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "queries": queries,
        "candidates": len(candidates),
        "collected": collected,
        "skipped": skipped,
        "failed": failed,
        "api_calls": client.calls,
        "collected_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (tree_root / "_collection.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
