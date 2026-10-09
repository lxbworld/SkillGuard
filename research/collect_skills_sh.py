#!/usr/bin/env python3
"""Collect the L1 (skills.sh) listing for the Phase 0 study.

**This script does not run until skills.sh says yes.** It refuses to start
without `--i-have-permission`. The request is `vercel-labs/skills#2442`; see
research/DISCLOSURE.md.

What L1 is actually for, now that a page has been inspected: a skill page
carries **install counts and a growth sparkline** — the popularity dimension L3
(GitHub) cannot provide, and the one the study's stratification calls for — plus
the source repository. It does **not** carry a commit SHA, so it cannot pin a
version. L1 is therefore a *discovery and popularity* layer: this script writes
the listing, and the content is then pinned to a commit through GitHub, exactly
as the L3 collector does.

Where the URLs come from:

- `robots.txt` is `Allow: /` with `Disallow: /api/`, `/search`, `/internal/`,
  `/debug-security/`, and a `Sitemap:` line. So we walk the sitemap and never
  touch the disallowed paths.
- The sitemap index lists `sitemap-misc`, `sitemap-owners`, `sitemap-skills-1`
  and `sitemap-skills-2`; the two skill sitemaps are on the order of 20,000
  URLs.

Ethics: read-only, rate-limited, `robots.txt` respected, `Retry-After` honoured,
and the output is a listing — paths and counts — not redistributed content.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = "https://www.skills.sh"
SITEMAP = f"{BASE}/sitemap.xml"
USER_AGENT = "SkillGuard-corpus (https://github.com/lxbworld/SkillGuard)"

# One request per second. The site publishes no limit; this is deliberately
# slower than any plausible one, and `Retry-After` overrides it.
MIN_CALL_INTERVAL = 1.0

NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

# `"interactionStatistic":{...,"userInteractionCount":3759755}` — the schema.org
# install counter, the cleanest number on the page.
INSTALLS_RE = re.compile(r'"userInteractionCount"\s*:\s*(\d+)')
# The repository panel links to the canonical source.
REPO_RE = re.compile(r'href="(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"')
FIRST_SEEN_RE = re.compile(r'"First Seen"[^,]*?"children"\s*:\s*"([^"]+)"', re.S)
STARS_RE = re.compile(r'"GitHub Stars"[^,]*?"children"\s*:\s*"([^"]+)"', re.S)


def require_permission(args: argparse.Namespace) -> None:
    if not args.i_have_permission:
        sys.exit(
            "refusing to collect: pass --i-have-permission once skills.sh has\n"
            "answered vercel-labs/skills#2442. Absence of a prohibition is not\n"
            "permission (research/PROTOCOL.md)."
        )


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After") or 60)
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


def sitemap_locs(url: str) -> list[str]:
    root = ET.fromstring(get(url))
    return [loc.text.strip() for loc in root.findall(".//sm:loc", NS) if loc.text]


def skill_urls() -> list[str]:
    """Every skill URL in the index's skill sitemaps, in sitemap order."""
    out: list[str] = []
    for child in sitemap_locs(SITEMAP):
        if "skills-" not in child:
            continue
        out.extend(sitemap_locs(child))
        time.sleep(MIN_CALL_INTERVAL)
    return out


def parse_page(html: str) -> dict:
    installs = INSTALLS_RE.search(html)
    repo = REPO_RE.search(html)
    stars = STARS_RE.search(html)
    first_seen = FIRST_SEEN_RE.search(html)
    return {
        "installs": int(installs.group(1)) if installs else None,
        "repo": repo.group(1).removeprefix("https://github.com/") if repo else None,
        "stars": stars.group(1).strip() if stars else None,
        "first_seen": first_seen.group(1).strip() if first_seen else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="research/lists/skills-sh.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="0 = the whole sitemap")
    ap.add_argument(
        "--i-have-permission",
        action="store_true",
        help="required: asserts skills.sh has granted the request in issue #2442",
    )
    args = ap.parse_args()
    require_permission(args)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    urls = skill_urls()
    if args.limit:
        urls = urls[: args.limit]
    print(f"{len(urls)} skill URLs; writing {out_path}", file=sys.stderr)

    done = 0
    failed = 0
    with out_path.open("w") as fh:
        for i, url in enumerate(urls, 1):
            parts = url.removeprefix(f"{BASE}/").split("/")
            if len(parts) != 3:
                continue
            owner, repo_slug, skill = parts
            try:
                meta = parse_page(get(url))
            except Exception as exc:  # noqa: BLE001 - record and continue
                failed += 1
                print(f"  {url}: {exc}", file=sys.stderr)
                time.sleep(MIN_CALL_INTERVAL)
                continue
            row = {
                "source_id": f"skills.sh/{owner}/{repo_slug}/{skill}",
                "layer": "L1",
                "owner": owner,
                "repo_slug": repo_slug,
                "skill": skill,
                "url": url,
                **meta,
            }
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            fh.flush()
            done += 1
            if i % 100 == 0:
                print(f"  [{i}/{len(urls)}] ok={done} failed={failed}", file=sys.stderr)
            time.sleep(MIN_CALL_INTERVAL)

    print(json.dumps({"listed": done, "failed": failed, "out": str(out_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
