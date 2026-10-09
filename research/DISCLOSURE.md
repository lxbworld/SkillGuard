# Coordination disclosure record

**Status**: protocol established; registry contact **not yet sent** (issue #5).
Contact is a human action. The messages are drafted below so that sending them
is a copy-paste, not a blank page.

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

> **Subject: research request — automated enumeration of the skills.sh index**
>
> Hello,
>
> I maintain SkillGuard (<https://github.com/lxbworld/SkillGuard>), an offline,
> deterministic static analyser for Agent Skills. I am planning a public
> security measurement of the skill ecosystem and would like to include
> skills.sh.
>
> What I am asking:
>
> 1. Permission to enumerate the public index at a low rate (about 1 request
>    per second, well under any published limit), respecting robots.txt and
>    your rate limits.
> 2. If you prefer, a bulk export or a documented research endpoint instead. Any
>    format you already have would be easier for both of us.
>
> What I would store: repo/skill path, the full commit SHA, and a content
> digest. Not content, not author identity, not download counts beyond what a
> public leaderboard already shows.
>
> What I would publish: aggregate, per-rule prevalence and a public dataset
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
> [name]

### 2.2 ClawHub

**Channel**: `openclaw/clawhub`. For genuinely malicious or deceptive *listings*
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
| skills.sh | GitHub discussion on `vercel-labs/skills` (no email, no `SECURITY.md`) | not yet | — | excluded until reply |
| ClawHub | `openclaw/clawhub` — Discord `discord.gg/clawd` or a repo issue; listing reports for findings | not yet | — | excluded until reply |
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
