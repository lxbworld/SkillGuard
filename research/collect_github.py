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
import hashlib
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
            except Exception:
                # A dropped connection is transient. A batch of thousands of
                # requests will meet one eventually, and it must not abort the
                # batch: retry, then give up on this call only.
                time.sleep(3 * (attempt + 1))
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
                # 404 and anything else: this file cannot be fetched. The caller
                # records the skill as failed and moves on.
                return None
            except Exception:
                # RemoteDisconnected, timeouts, TLS resets: transient. Retry.
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
    ap.add_argument(
        "--per-query",
        type=int,
        default=250,
        help="max candidates to take from each query (the API caps at 1000)",
    )
    ap.add_argument("--tree", default="research/raw", help="where to write the fetched bytes")
    ap.add_argument(
        "--query",
        action="append",
        default=None,
        help="GitHub code-search query; repeatable to diversify the sample",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if not args.query:
        # Several `path:` variants, because `filename:SKILL.md` alone is
        # dominated by "the whole repository is the skill" monorepos and by
        # whatever GitHub indexed most recently.
        args.query = [
            "filename:SKILL.md",
            "filename:SKILL.md path:skills",
            "filename:SKILL.md path:.claude",
            "filename:SKILL.md path:agent",
            "filename:SKILL.md path:agents",
            "filename:SKILL.md path:.cursor",
            "filename:SKILL.md path:plugins",
            "filename:SKILL.md path:commands",
            "filename:SKILL.md path:.github",
            "filename:SKILL.md path:templates",
            "filename:SKILL.md path:skills/",
            "filename:SKILL.md path:.codex",
        ]

    client = Client(token(), verbose=args.verbose)
    tree_root = Path(args.tree)
    tree_root.mkdir(parents=True, exist_ok=True)
    provenance_path = tree_root / "_provenance.jsonl"

    # Systematic sample: take the candidates in a fixed order that does not
    # depend on which query returned them, so the draw is reproducible and not
    # biased by query order. (Protocol §2.2 calls for systematic sampling for
    # over-capacity strata; this is the same idea at the collection step.)
    print(f"searching GitHub for up to {args.limit} skills ...", file=sys.stderr)
    seen_keys: set[tuple[str, str]] = set()
    per_query_counts: dict[str, int] = {}
    for q in args.query:
        found = search_skills(client, q, args.per_query)
        for cand in found:
            seen_keys.add((cand["repo"], cand["skill_dir"]))
        per_query_counts[q] = len(found)
        print(f"  {len(found):5d}  {q}", file=sys.stderr)

    candidates = [
        {"repo": repo, "skill_dir": skill_dir} for repo, skill_dir in seen_keys
    ]
    candidates.sort(
        key=lambda c: hashlib.sha256(
            f"{c['repo']}/{c['skill_dir']}".encode()
        ).hexdigest()
    )
    candidates = candidates[: args.limit]
    print(
        f"  {len(seen_keys)} unique candidates, sampling {len(candidates)}",
        file=sys.stderr,
    )

    repo_cache: dict[str, tuple[str, dict[str, dict], bool]] = {}
    provenance: list[dict] = []
    done: dict[str, dict] = {}
    if provenance_path.exists():
        with provenance_path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    row = json.loads(line)
                    provenance.append(row)
                    done[row["path"]] = row
        print(f"  resuming: {len(done)} skills already collected", file=sys.stderr)
    collected = 0
    skipped = failed = 0
    prov_fh = provenance_path.open("a")

    for i, cand in enumerate(candidates, 1):
        repo = cand["repo"]
        skill_dir = cand["skill_dir"]
        owner, name = repo.split("/", 1)

        rel_path = f"{repo}/{skill_dir}" if skill_dir else repo
        if rel_path in done:
            continue

        try:
            if repo not in repo_cache:
                head = client.get_json(f"/repos/{repo}/commits/HEAD")["sha"]
                tree = client.get_json(f"/repos/{repo}/git/trees/{head}?recursive=1")
                entries = {
                    e["path"]: e
                    for e in tree.get("tree", [])
                    if e.get("type") == "blob" and e.get("mode") != "120000"
                }
                # A repo-root license covers every skill in the repo, and the
                # corpus tree is not a git checkout, so the scanner cannot find
                # it. Record it here; `corpus scan` uses it to avoid the
                # LICENSE_MISSING false positive measured on real data.
                root_files = {
                    e["path"].lower()
                    for e in tree.get("tree", [])
                    if e.get("type") == "blob" and "/" not in e["path"]
                }
                root_license = any(
                    n.startswith("license") or n.startswith("copying") or n == "notice"
                    for n in root_files
                )
                repo_cache[repo] = (head, entries, root_license)
            commit, entries, root_license = repo_cache[repo]
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
        try:
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
        except Exception as exc:
            # A hostile or unusual path must not abort a 1000-skill batch.
            failed += 1
            print(f"  [{i}] {rel_path}: fetch/write error {exc}", file=sys.stderr)
            continue

        row = {
            "path": str((tree_root / repo / skill_dir).relative_to(tree_root)),
            "repo": repo,
            "commit": commit,
            "skill_dir": skill_dir,
            "files": len(members),
            "bytes": total,
            "root_license": root_license,
        }
        provenance.append(row)
        done[row["path"]] = row
        prov_fh.write(json.dumps(row, sort_keys=True) + "\n")
        prov_fh.flush()
        collected += 1
        if i % 25 == 0 or i == len(candidates):
            print(
                f"  [{i}/{len(candidates)}] collected={collected} "
                f"skipped={skipped} failed={failed}",
                file=sys.stderr,
            )

    prov_fh.close()
    # Rewrite sorted and deduplicated (last wins), so the committed sidecar is
    # stable even after several resumed runs.
    by_path = {row["path"]: row for row in provenance}
    provenance = [by_path[k] for k in sorted(by_path)]
    with provenance_path.open("w") as fh:
        for row in provenance:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "queries": args.query,
        "per_query_counts": per_query_counts,
        "unique_candidates": len(seen_keys),
        "sample": len(candidates),
        "candidates": len(candidates),
        "collected": len(provenance),
        "collected_this_run": collected,
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
