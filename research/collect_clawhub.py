#!/usr/bin/env python3
"""Collect an L2 (ClawHub) corpus for the Phase 0 study.

**This script does not run until ClawHub says yes.** It refuses to start without
`--i-have-permission`, so it cannot be run by accident, by a cron, or by a
future reader who assumes the permission exists. See research/DISCLOSURE.md for
the state of that request (`openclaw/clawhub#3931`).

ClawHub documents a bulk export meant for exactly this:

    GET /api/v1/skills/export      (docs/http-api.md)
      auth:    API token required
      params:  startDate, endDate (Unix ms on updatedAt), limit (1-250), cursor
      returns: ZIP, each skill rooted at {publisher}/{slug}/
               _manifest.json at the root
               _source_handoff.json per GitHub-backed skill, carrying
                 repo, commit, path, content hash, archive URL

That is a better substrate than crawling: it is server-rendered, its files are
bound to a signed manifest by path/size/SHA-256, and it hands back the **commit**
and **content hash** the protocol requires instead of a page we would have to
resolve ourselves. So the work here is mostly extraction, not collection.

Why an export and not the paginated listing: the listing gives a skill's current
state, which moves. The export gives a versioned snapshot with a source commit,
which is the thing `corpus reproduce` can re-derive.

Ethics: no content is stored beyond `--tree` (gitignored), nothing downloaded is
executed, and the committed artefact remains path + commit + digest.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

API = "https://clawhub.ai/api/v1/skills/export"
USER_AGENT = "SkillGuard-corpus (https://github.com/lxbworld/SkillGuard)"

# The documented ceiling is 250. Ask for it: fewer, larger responses is the
# polite direction, not more, smaller ones.
PAGE = 250

# Between pages. The docs allow 3000 read requests/minute per IP, so this is
# roughly 1/50th of the budget; the limit is not the constraint, care is.
MIN_CALL_INTERVAL = 2.0

# A skill bigger than this is skipped and recorded, never truncated: truncating
# would silently change the digest (same rule as collect_github.py).
MAX_SKILL_BYTES = 1536 * 1024
MAX_SKILL_FILES = 80


def token() -> str:
    tok = os.environ.get("CLAWHUB_TOKEN", "").strip()
    if not tok:
        sys.exit(
            "no ClawHub token. The export endpoint requires one:\n"
            "  export CLAWHUB_TOKEN=clh_...\n"
            "See research/DISCLOSURE.md for the state of the permission request."
        )
    return tok


def require_permission(args: argparse.Namespace) -> None:
    if not args.i_have_permission:
        sys.exit(
            "refusing to collect: pass --i-have-permission once ClawHub has\n"
            "answered openclaw/clawhub#3931. Absence of a prohibition is not\n"
            "permission (research/PROTOCOL.md)."
        )


def fetch(url: str, tok: str) -> bytes:
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {tok}", "User-Agent": USER_AGENT}
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After") or 30)
                print(f"  429, honouring Retry-After: {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if 500 <= exc.code < 600:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"gave up after 5 attempts: {url}")


def export_pages(tok: str, start_ms: int, end_ms: int):
    """Yield (zip_bytes, next_cursor) until the cursors run out."""
    cursor = None
    while True:
        q = {"startDate": start_ms, "endDate": end_ms, "limit": PAGE}
        if cursor:
            q["cursor"] = cursor
        url = f"{API}?{urllib.parse.urlencode(q)}"
        body = fetch(url, tok)
        # The cursor arrives in a header, not the ZIP, so ask for it separately
        # by watching for the next-page signal. When the server has no more, it
        # omits the header and we stop.
        next_cursor = exported_cursor(body)
        yield body, next_cursor
        if not next_cursor:
            return
        cursor = next_cursor
        time.sleep(MIN_CALL_INTERVAL)


def exported_cursor(zip_bytes: bytes) -> str | None:
    """Read `_manifest.json` for a `nextCursor`, if the export uses one.

    ClawHub's docs name a `cursor` request parameter but do not pin where the
    response carries the next one. Read the manifest rather than guess, and
    treat "absent" as "no more pages" — over-reading a registry is worse than
    stopping early and reporting a partial draw.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            raw = zf.read("_manifest.json")
    except (zipfile.BadZipFile, KeyError):
        return None
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError:
        return None
    for key in ("nextCursor", "next_cursor", "cursor"):
        value = manifest.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def extract(zip_bytes: bytes, tree_root: Path, prov_fh) -> dict:
    """Write one archive under `tree_root`, returning per-run counts."""
    stats = {"collected": 0, "skipped": 0, "failed": 0}
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        print(f"  discarded a partial archive: {exc}", file=sys.stderr)
        stats["failed"] += 1
        return stats

    with zf:
        names = zf.namelist()
        # Group by "{publisher}/{slug}/".
        skills: dict[str, list[str]] = {}
        for name in names:
            parts = name.split("/")
            if len(parts) >= 3 and parts[2]:
                skills.setdefault("/".join(parts[:2]), []).append(name)

        for key, members in skills.items():
            files = [m for m in members if not m.endswith("/") and "_" not in Path(m).name[:1]]
            total = sum(zf.getinfo(m).file_size for m in files)
            if total > MAX_SKILL_BYTES or len(files) > MAX_SKILL_FILES:
                stats["skipped"] += 1
                print(f"  {key}: skipped ({len(files)} files, {total} bytes)", file=sys.stderr)
                continue

            dest = tree_root / key
            dest.mkdir(parents=True, exist_ok=True)
            try:
                for member in files:
                    target = dest / Path(member).relative_to(key)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zf.read(member))
            except OSError as exc:
                stats["failed"] += 1
                print(f"  {key}: write error {exc}", file=sys.stderr)
                continue

            row = {
                "path": key,
                "layer": "L2",
                "repo": None,
                "commit": None,
                "skill_dir": Path(key).name,
                "files": len(files),
                "bytes": total,
                "root_license": None,
            }
            # The handoff file is the only place the source repo and commit
            # appear; without it the skill is not reproducible to a commit.
            handoff = dest / "_source_handoff.json"
            if handoff.exists():
                try:
                    meta = json.loads(handoff.read_text())
                    row["repo"] = meta.get("repo")
                    row["commit"] = meta.get("commit")
                    row["content_hash"] = meta.get("contentHash") or meta.get("content_hash")
                except (OSError, json.JSONDecodeError):
                    pass
                handoff.unlink()

            prov_fh.write(json.dumps(row, sort_keys=True) + "\n")
            prov_fh.flush()
            stats["collected"] += 1
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tree", default="research/raw", help="where skill bytes land")
    ap.add_argument("--start", default="2026-01-01", help="UTC date, lower bound on updatedAt")
    ap.add_argument("--end", default=None, help="UTC date, default: now")
    ap.add_argument(
        "--i-have-permission",
        action="store_true",
        help="required: asserts ClawHub has granted the request in issue #3931",
    )
    args = ap.parse_args()
    require_permission(args)

    tok = token()
    tree_root = Path(args.tree)
    tree_root.mkdir(parents=True, exist_ok=True)
    prov_fh = (tree_root / "_provenance.jsonl").open("a")

    start_ms = int(time.mktime(time.strptime(args.start, "%Y-%m-%d")) * 1000)
    end_ms = int(time.time() * 1000)

    total = {"collected": 0, "skipped": 0, "failed": 0}
    pages = 0
    for body, _cursor in export_pages(tok, start_ms, end_ms):
        pages += 1
        got = extract(body, tree_root, prov_fh)
        for k in total:
            total[k] += got[k]
        print(
            f"  page {pages}: collected={total['collected']} "
            f"skipped={total['skipped']} failed={total['failed']}",
            file=sys.stderr,
        )
        time.sleep(MIN_CALL_INTERVAL)

    prov_fh.close()
    print(json.dumps({"pages": pages, **total}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
