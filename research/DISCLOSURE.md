# Coordination disclosure record

**Status**: protocol established; **all three registry requests sent 2026-10-09**
(issue #5). Contact is a human action. The messages are drafted below so that
sending them is a copy-paste, not a blank page.

This file is the D11 deliverable of `docs/PHASE0_CORPUS_STUDY.md` and the
disclosure rules of `research/PROTOCOL.md` §8, recorded as they actually happen.

---

## 1. Why this page exists

Two things are true at once:

- A public security measurement of the Agent Skill ecosystem is worth doing and
  nobody has done it at scale.
- Publishing a registry's prevalence figure without telling its operators first
  is how a legitimate finding becomes an incident.

So the order is fixed: **find privately, notify, wait 7 days, then publish
digests only.** No payloads, ever. Only `rule id`, `content digest`, `file`,
`line`.

Contributing back is the point. A registry that gets a private heads-up is a
cooperator; a registry that reads it on Hacker News is a victim. The first is a
long-term relationship and the more valuable outcome.

---

## 2. Registry permission requests (issue #5)

Each request below is deliberately short and concrete. The five points are the
ones `#5` requires: what we are doing, what we want, what we store, what we will
report and when, and what we will *not* publish.

### 2.1 skills.sh

**Channel**: no email and no `SECURITY.md` in `vercel-labs/skills` (the operator
repo behind skills.sh, per its homepage). Open a GitHub **discussion** or issue
there. Vercel Labs owns the repo, so the maintainers are the operators.

**What their own files say** (checked 2026-10-09, so the message can cite them
instead of guessing):

- `https://skills.sh/robots.txt` — `Allow: /` with `Disallow: /api/`,
  `Disallow: /search`, `Disallow: /internal/`, `Disallow: /debug-security/`, and
the `Sitemap:` line pointing at `https://www.skills.sh/sitemap.xml`.
- That sitemap is an index of four sitemaps; `sitemap-skills-1.xml` alone lists
**10,000** skill URLs (876 KB), so the index is on the order of 20,000. A
published, crawler-addressed sitemap is the intended route — which is why the
request is framed as "may I walk your sitemap", not "may I use your API".
- `.github/ISSUE_TEMPLATE/config.yml` sets `blank_issues_enabled: true`, and the
three templates (`agent-request`, `bug-report`, `feature-request`) do not fit,
so this is a blank issue.

> **Subject: research request — automated enumeration of the skills.sh index**
>
> Hello,
>
> I maintain SkillGuard (<https://github.com/lxbworld/SkillGuard>), an offline,
> deterministic static analyser for Agent Skills. I am planning a public
> security measurement of the skill ecosystem and would like to include
> skills.sh.
>
> Your `robots.txt` allows `/` but disallows `/api/` and `/search`, and points at
> `sitemap.xml`. I read that as "walking the sitemap is fine, the API is not",
> so that is what I am asking about: may I fetch the sitemap and its entries at a
> low rate — about 1 request per second — storing a content digest per skill? I
> will not touch `/api/`, `/search` or `/internal/`, and I will honour
> `Retry-After` and slow down further if you ask.
>
> If you would rather give me a bulk export, or an endpoint meant for this, that
> is easier for both of us and I would prefer it.
>
> What I would store: repo/skill path, the full commit SHA, and a content
> digest. Not content, not author identity, not anything beyond what the public
> listing already shows.
>
> What I would publish: aggregate per-rule prevalence, and a public dataset
> containing digests and rule ids only.
>
> What I would do before publishing anything about skills.sh specifically: send
> you the findings privately and give you 7 days to respond. If you prefer, I
> will give you the findings privately and publish nothing that identifies your
> index at all. If you want something removed, I will remove it and re-run.
>
> This is a request, not a notification: I will not collect until you reply.
> Absence of a prohibition is not permission.
>
> Thank you,
> lxbworld
> <https://github.com/lxbworld/SkillGuard>

### 2.2 ClawHub

**Channel**: [RFC `openclaw/clawhub#3931`](https://github.com/openclaw/clawhub/issues/3931),
sent 2026-10-09. The repo's **RFC** template was chosen over a plain issue or the
Discord because its own description decided it — *"Use RFCs for decisions that
need visible feedback before they become policy, product behavior, or public API
contract"* — and "may researchers enumerate your index" is exactly such a
decision. It lands in their triage as `type: rfc` / `status: review`, where a
plain issue among ~3,900 would not. Discord (`discord.gg/clawd`, the OpenClaw
guild, ~177k members) stays in reserve as a nudge if the RFC goes quiet.

For genuinely malicious or deceptive *listings*
its `SECURITY.md` names **listing reports** as the channel, not advisories —
that applies to what the study finds, not to the standing permission below. Ask
for the permission in the community **Discord** (`discord.gg/clawd`) or an issue
on the repo. Note the policy sentence that matters here: *"Do not use ClawHub
advisories for vulnerabilities in a third-party skill or plugin's own source
code. Report those directly to the publisher or source repository."* That is
exactly the study's subject matter, so the operator conversation has to happen
first.

> **Subject: research request — private findings before publication (ClawHub)**
>
> Hello,
>
> I maintain SkillGuard (<https://github.com/lxbworld/SkillGuard>), an offline
> static analyser for Agent Skills. Independent audits have already found
> malicious skills on ClawHub, which makes it the most security-relevant index
> to measure — and the one where a careless publication could disrupt your
> moderation.
>
> I would like to:
>
> 1. Enumerate the public index at a low rate, or use any export you would
>    rather provide.
> 2. Report anything malicious **to you first**, privately, with a 7-day window
>    before it appears anywhere public.
> 3. Publish only digests, rule ids and aggregate counts — never payloads,
>    never a runnable sample, never author identity.
>
> If you would rather I publish nothing specific to ClawHub, I will hand you the
> findings privately and only report ecosystem-wide aggregates.
>
> Would you like a point of contact for takedown coordination? I am happy to
> follow your process, whatever it is.
>
> Thank you,
> [name]

### 2.3 skillsmp.com

**Channel**: `support@skillsmp.com` (from the site's own `mailto:` link). The
only one of the three with a plain email address.

> **Subject: research request — may I enumerate skillsmp.com?**
>
> Hello,
>
> I maintain SkillGuard (<https://github.com/lxbworld/SkillGuard>), an offline
> static analyser for Agent Skills, and I am planning a public security
> measurement of the ecosystem.
>
> I could not find a published policy on automated collection, so I am asking
> rather than assuming. May I enumerate your public index at about 1 request per
> second (or use an export/API you prefer)?
>
> I store only path, full commit SHA and content digest — no content, no author
> identity. I report malicious findings to you privately with a 7-day window
> before publication, and I publish digests and rule ids only, never payloads.
>
> If the answer is no, I will exclude skillsmp.com from the corpus and say so
> explicitly in the report. Either way, thank you for reading.
>
> [name]

---

## 3. Status

| Source | Contact route | Sent | Reply | Decision |
|---|---|---|---|---|
| skills.sh | GitHub issue [#2442](https://github.com/vercel-labs/skills/issues/2442) on `vercel-labs/skills` (no email, no `SECURITY.md`) | **2026-10-09** | — | excluded until reply |
| ClawHub | RFC [openclaw/clawhub#3931](https://github.com/openclaw/clawhub/issues/3931) — `type: rfc`, `status: review` | **2026-10-09** | automated review 2026-10-09; **recommends standing terms**; policy owner pending | excluded until reply |
| skillsmp.com | `support@skillsmp.com` | **2026-10-09** | — | excluded until reply |
| GitHub (L3) | n/a — API docs | n/a | n/a | **permitted**, proceed |

While these are unanswered, the study runs on **L3 only**
(`research/TERMS-REVIEW.md` §"Net effect"). That is a lower bound, and the
report says so.

---

## 4. Disclosure timeline (to be filled as it happens)

Each entry records: date (UTC), what was found, to whom it was reported, the
response deadline, and the outcome. Only digests and rule ids are recorded here;
the evidence stays on the scanning machine.

| Date (UTC) | Finding | Reported to | Deadline | Outcome |
|---|---|---|---|---|
| 2026-10-09 | permission request, no finding yet | skillsmp.com `support@` | 2026-10-16 | awaiting reply |
| 2026-10-09 | permission request, no finding yet | skills.sh — `vercel-labs/skills` issue #2442 | 2026-10-16 | awaiting reply |
| 2026-10-09 | permission request, no finding yet | ClawHub — RFC `openclaw/clawhub#3931` | 2026-10-23 | awaiting policy owner |
| 2026-10-09 | reply accepting the re-identification point, narrowing the ask to publication terms | ClawHub — comment 6075720307 | — | sent |

The request cites <https://github.com/lxbworld/SkillGuard>, which became public on
2026-10-09 so that the link in the message resolves.

---

## 5. Rules this page enforces

1. **Notify before publishing.** Always. A 7-day response window.
2. **Digests and rule ids only.** Never a payload, never a working sample,
   never author identity.
3. **No prevalence figure for a registry that has not been contacted.** Not
   "we tried": contacted and either answered or the window elapsed.
4. **A removal request is honored**, and the study re-runs.
5. **A cooperator is credited** if they want to be. Going public with the fix is
   a better story than going public with the hole.

---

## 6. What ClawHub's review changed (2026-10-09)

`openclaw/clawhub#3931` got an automated maintainer-side review within five
minutes. Two of its points need recording because they are correct.

### 6.1 The re-identification point — our wording was too strong

The review: *"paths, commit SHAs, and digests can link findings back to public
publishers despite omitting author names."*

That is right, and the drafts above said **"not author identity"**, which is not
something we can deliver. A repo path plus a commit SHA identifies the artifact,
and through it the publisher, however carefully names are dropped. The protocol
was already narrower than its own summary — `PROTOCOL.md` says *"`commit` author
metadata discarded in the public dataset"* and *"no author profiling"*, which is
true — but "not author identity" is not.

Corrected wording for any message from here on:

> No author names, no commit-author metadata, no email addresses. I publish rule
> id, content digest and path — which does identify the artifact, and I say so
> rather than claiming anonymity. If the registry prefers, aggregates only is an
> acceptable outcome, and I will not publish a path at all.

### 6.2 The RFC asked the wrong question — access was already granted

ClawHub's own `docs/api.md` already decides collection:

> *"You can build a third-party catalog, directory, or search surface on top of
> ClawHub's public read APIs."*

with `Read: 3000/min per IP, 12000/min per key`, public read requiring no token,
and a deterministic enumeration route (`GET /api/v1/skills?prefix=&cursor=`,
continue with `nextCursor`). Our request asked to crawl at **1 request per
second**, which is 1/50th of what their docs already allow.

So the reviewed summary was exactly right: *"Existing catalog-reuse guidance
answers access mechanics, but does not settle research publication terms or a
disclosure window."*

**The ask narrows to publication terms**: may aggregates be published, may a
finding name an artifact, through which channel, and within what window. The
collector should use their documented read API rather than a crawler.

### 6.3 The review's recommendation

> **Publish standing research terms**: Permit public-surface research under
> existing API limits with explicit attribution, privacy, reporting, and
> publication conditions.

Labels applied: `type: rfc`, `status: review`, `clawhub:needs-product-decision`,
`clawhub:needs-security-review`, `impact:security`. It is with a policy owner now.

### 6.4 The bulk export endpoint is the intended route

The review pointed at `docs/http-api.md`, which documents an endpoint
purpose-built for this study:

```
GET /api/v1/skills/export      # "Bulk export of latest public skills for offline analysis"
  auth:    API token required
  params:  startDate, endDate (Unix ms on updatedAt), limit (1-250, default 250), cursor
  returns: ZIP, each skill rooted at {publisher}/{slug}/
           _manifest.json at the root
           _source_handoff.json per GitHub-backed skill, carrying
             repo, commit, path, content hash, archive URL
           every hosted file bound to a signed manifest by path, size and SHA-256
```

This is better than crawling on every axis that matters here: it is
server-rendered and reproducible, it hands back the **commit and content hash**
the protocol requires rather than a page we would have to resolve ourselves, and
the integrity of the archive is signed, so a truncated stream is detected rather
than silently half-read.

It also gives ClawHub the control point that makes "yes" cheap: the token can be
rate-limited, scoped, revoked, or issued for a fixed window without writing a
standing policy first. Whatever the policy answer is, **this is the mechanism to
ask about**, not `prefix`/`cursor` pagination.

### 6.5 Discord is not used

The OpenClaw Discord (`discord.gg/clawd`, ~177k members) was held in reserve as
a nudge if the RFC went quiet. It did not: an automated review landed in five
minutes and the thread is now with a policy owner. **Sending it would be noise**,
so it is dropped. It stays recorded here only so a future reader knows it was
considered and why it was not used.
