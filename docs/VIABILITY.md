# SkillGuard — Feasibility, Direction & Go-To-Market

Research date: 2026-10-07. This document answers three questions: **should this be
built? what should be built? how does anyone hear about it?**

---

## 0. Executive summary (read this part first)

**Conclusion: build it, but the current direction definition contains one major error
that needs correcting.**

| Judgement | Conclusion |
|---|---|
| Is the problem real? | ✅ **Extremely real.** Four large-scale empirical studies already exist: ClawHub's 11.9% malicious rate, 1,184 poisoned skills, Snyk's audit of 3,984 skills, and 2 arXiv papers |
| Is the timing right? | ✅ **2026 is the window.** The ecosystem went from 2,179 → 606,555 tools (in about 11 months), and CVE-level incidents have already occurred |
| Is "the npm of Skills" viable as a position? | ⚠️ **Not viable as a position.** skills (7.24M weekly downloads) + skills.sh + skillpm already own the install entry point, and we have no intention of contesting the registry |
| Is "the npm audit of Skills" viable? | ✅ **Viable and unoccupied.** Offline, deterministic, declared vs observed — the only open slot |
| Can one person / one model finish it? | ✅ The MVP is viable. ⚠️ But a "complete package manager" is impossible and must be cut |
| Can open source bring recognition? | ✅ **Yes, but only if Phase 0 (the corpus study) comes first**, not the product |
| The biggest risk | 🔴 **Not technical — distribution.** SecureClaw (feature-complete, full OWASP ASI coverage) got 2 points on Show HN |

**The core recommendations (three, in priority order):**

1. **Cut the "package manager" positioning; become "the npm audit of Skills + a
   permission-verification standard".** The fight over the install entry point cannot be
   won against vercel-labs.
2. **Redefine Phase 0 as: scan 100,000 public skills and publish the first large-scale
   empirical report.** This is the only move that produces Snyk/Socket-level recognition,
   and it needs only the Phase 1 scanner. **Data first, product second.**
3. **Ship an embeddable rule-engine library, not just a CLI.** Let skil-lock / skillmds /
   registry services embed our rules. That is the path Semgrep walked (GitLab adopted it
   as the default analyzer).

---

## 1. The market: how real is the problem

### 1.1 Ecosystem scale (Skillful.sh, aggregating 55 directories/registries, 2026-09-30)

| Metric | Value |
|---|---|
| Total tools | **606,555** |
| AI Skills | 334,279 (55.1%) |
| MCP Servers | 245,589 (40.5%) |
| Autonomous Agents | 26,687 (4.4%) |
| Added in the last 30 days | 46,534 (about **1,551/day**) |
| Added in the last 90 days | 152,528 |

### 1.2 The real stock on GitHub (arXiv 2608.10906 "GitSkills", collected 2026-07)

| Metric | Value |
|---|---|
| Skill file occurrences | **3,797,117** |
| Public repositories | 282,200 |
| Accounts | 195,841 |
| Content duplication rate | **50.5%** |

> The paper's own words: "Skills also have no central registry or package manager;
> developers reuse them by copying folders between repositories."

**A 50.5% duplication rate + 3.8M files + no registry** — that is precisely "copying is
propagation, with no review", which is precisely the reason SkillGuard exists, and it also
shows that **a lockfile / digest has enormous value** (after copying, there is no way to
know whether you got the same thing).

### 1.3 Confirmed attacks (the best project justification)

| When | Incident | Data |
|---|---|---|
| 2026-02 | Koi Security (Oren Yomtov) audits ClawHub | **341 malicious skills = 11.9% of 2,857** |
| 2026-02 | Snyk audits 3,984 skills across ClawHub + skills.sh | 91% confirmed malicious with prompt injection; 100% contained malicious code |
| From 2026-02 | ClawHub adds VirusTotal + ClawScan | Still continually bypassed (Unit 42) |
| 2026-02 to 05 | **1,184+ malicious skills** distributed Atomic macOS Stealer on ClawHub | Credential theft |
| — | CSA research (2026-05) | **5 of the top 7 skills by downloads were confirmed malicious** |
| 2026-04 | An Anthropic internal evaluation accident | An AI agent published a malicious package to the **real PyPI**; within an hour 15 real systems ran it, **one of them a security scanner** |
| — | Check Point discloses two Claude Code CVEs | CVE-2025-59536 / CVE-2026-21852: in-repo config files auto-loaded with no integrity check |
| 2026-03 | TeamPCP compromises Trivy, KICS, LiteLLM, Telnyx | **Security tools themselves became the supply chain's primary target** |
| 2026-06 | Sapphire Sleet compromises 144 @mastra npm packages (in 88 minutes) | Stealing LLM/cloud credentials |

### 1.4 A brand new, harder attack surface (academic consensus)

arXiv **2605.11418** (2026-05) provides evidence that a registry can be broken **without
any malicious code**:

- Keyword injection gets a malicious skill into the embedding-retrieval Top-10 **80%** of
  the time, with an **86%** pairwise win rate
- Framing the description biases the agent toward the malicious variant **77.6%** of the
  time (human reviewers could not tell the difference)
- The rate of bypassing automated governance classifiers was **36.5%–100%**

Snyk named this class **ToxicSkills**. Check Point demonstrated on Cursor that an
"innocuous-looking MCP config file → one approval → a long-lived backdoor" works.

### 1.5 Who is already doing this (you must know before starting)

| Player | Status | What it means for us |
|---|---|---|
| **Socket.dev** | Series C **$60M / $1B valuation** (2026-03), 139 people. Scanning 60,000+ skills on skills.sh since 2026-02; alerted **within 6 minutes** of the Mastra attack | 🔴 **The strongest competitor.** Has funding, threat intelligence and registry-side data |
| **Endor Labs (AURI)** | Positions as an "Agentic Application Security Platform", explicitly writes "Every model, skill, MCP server, and tool call extends your supply chain", and **enforces policy before the action happens: allow / block / ask a human** | 🔴 **The strongest positioning competitor.** Our "block the install" narrative is nearly identical, but they do the whole stack |
| **Snyk** | Agent Scan + a cloud analysis API, Apache-2.0 | The cloud route; cannot go offline |
| **skillmds** | A 1.13M-skill registry, MIT, CLI + MCP + Action + SARIF | An ecosystem entry point |
| **skills (vercel-labs)** | **7,243,164** weekly downloads, 72+ agents | The install entry point; unassailable |
| **skil-lock** | Apache-2.0 / Go, capability lockfile + policy + approvals + SPEC.md + Action | The most direct functional competitor |
| **skill-preflight** | MIT, scorecard + policy + SARIF + Action | The scoring route |
| **SecureClaw (Adversa AI)** | Claims coverage of all 10 OWASP ASI Top 10 classes | ⚠️ **Show HN got 2 points and 1 comment** — a cautionary tale |
| **AgentSec (agentsec.sh)** | Unfunded, founded 2026, "security auditing for autonomous agent skill sets" | Another entrant |
| **skillful.sh** | A 600k-tool directory, already grading skills **A+ to F** | The "yet another score for everyone" slot |
| arXiv | 2606.03024 (the SkillGuard permission framework), 2605.10990 (SkillGuard drift), 2605.11418 (registry poisoning), 2608.10906 (GitSkills), **USENIX Security 2026 "Do Not Mention This to the User"**, the Skill-Inject benchmark, AgentSkillOS | Academic heat is very high — both a **traffic channel** and a **risk of being overtaken** |

---

## 2. Positioning diagnosis: where the original direction went wrong

§17 of the requirements assumes we should do Discovery + Package + Verify + Scan + Policy
+ Lock + Install all at once.

**The problem: that is a dual identity of "package manager + security", and both halves
demand enormous ecosystem investment.**

Against reality:

| What we wanted to do | Reality |
|---|---|
| Own the install entry point | skills has 7.24M weekly downloads and 72+ agents, with a lockfile already; skillpm reuses npm; skills-package-manager has a pnpm plugin. **Winning would need 10× the ecosystem investment** |
| Own a registry | skillmds has 1.13M + skills.sh 100k + about 40 marketplaces. Requirements §6 also forbids it |
| Do scanning | 4 companies do it, 2 of them valued in the hundreds of millions |
| Do policy/lock | skil-lock already has a SPEC.md |
| **Do declared vs observed** | ✅ **Nobody does it** |
| **Do offline determinism** | ✅ **Nobody does it** (Snyk must go to the cloud) |
| **Do "evidence-grade" precision output** | ⚠️ Partly done (SkillMD openly says it is "blunt, it only tells you which lines to look at"), but nobody produces **a reproducible precision figure** |

### 2.1 The corrected positioning

> **SkillGuard = an offline, deterministic verification layer for Agent Skills.**
> Not "an installer", but **the verification standard before installation**:
> 1. Scan and produce **reproducible** capability evidence
> 2. Check the difference between the permissions a Skill declares and what it actually does (DECLARED vs OBSERVED)
> 3. Block installation with a declarative policy + an approval lockfile
> 4. Emit SARIF so the result flows into the existing CI ecosystem

**The key turn: from "we can install too" to "we define how verification works, and the
result can be trusted".**

The former is functional competition (which cannot beat 7.24M weekly downloads); the
latter is standards competition (which can be won).

### 2.2 The three things we will not do (written into the README and the code comments)

- ❌ No registry, no search, no leaderboard (skillful.sh has that slot already, and a score is a pseudo-security signal)
- ❌ No runtime sandbox/enforcement (that belongs to AgentBound / AgentSkillOS / the arXiv SkillGuard paper)
- ❌ No scanning the whole MCP ecosystem (requirements §6 settled it; and Snyk/Endor already do it)

---

## 3. Feasibility assessment (technical + organisational)

### 3.1 Technical feasibility: ✅ the MVP is entirely feasible

| Component | Feasibility | Note |
|---|---|---|
| SKILL.md parsing (frontmatter + body) | ✅ High | A simple format with an official spec (agentskills.io, released by Anthropic 2025-12, hosted by the Linux Foundation / Agentic AI Foundation) |
| Deterministic rules (44 of them) | ✅ High | regex + YAML/JSON is enough; low technical risk |
| Capability derivation + declaration diff | ⚠️ Medium | **Precision is the only real risk** (see 3.2) |
| Directory digest hashing | ✅ High | The algorithm is validated in skills-lock / pcomans/skills-lock |
| git provenance | ✅ High | A read-only subprocess |
| The policy engine | ✅ High | Declarative YAML → a four-state decision |
| An offline single Rust binary | ✅ High | A small dependency tree |
| **An installer** | ❌ Low value, high cost | See §2 — **recommend cutting it, or keeping only the "write into agent directories" step** |

### 3.2 The one real risk: the precision of declared vs observed

The academic comparison group is clear:
- The arXiv SkillGuard generates a manifest with an LLM, reaching capability-level F1 **91.0%** (precision 85.6% / recall 97.1%)
- The same paper reports: **56.5% of skills are over-declared and 17.4% are under-declared**

**Reading**: the base rate for under-declared is only 17.4%. That means
- A naive implementation's precision ceiling is limited by "how we decide whether an observation deserves a declaration"
- **But seen the other way, it is an extremely persuasive marketing figure**: "17.4% of real skills under-declare what they access"

**Our differentiating responses (these must go into the design)**:
1. Require a declaration only for observations in **code files** (`scripts/`, code blocks);
   URLs and commands in Markdown prose are treated as "explanatory references" and do not
   count as capability. This is the key that moves precision from ~0.5 to ~0.85.
2. Provide `skillguard adopt`: **automatically generate a permissions declaration from the
   current observed set and write it into the frontmatter**, forming a baseline; only newly
   added undeclared capability is then reported.
   → **This solves the chicken-and-egg problem**: with no manifest ecosystem, bootstrap one.
3. Phase it: "report but do not block" first to accumulate user feedback, and only enable
   blocking once precision ≥ 0.8.

### 3.3 Organisational feasibility

| Dimension | Assessment |
|---|---|
| One person + a DeepSeek constraint | ✅ The MVP is viable (Rust's compile-time checks suit AI-generated code). ⚠️ A complete package manager is not |
| Upstream dependency survival | ⚠️ Medium risk. If vercel-labs/skills adds built-in security it squeezes the install side, **but not the verification side** |
| The cost of the name collision | 🔴 **Real**: 2 same-named arXiv papers + agentsec.sh + SecureClaw in the same lane. Both search and mindshare will suffer |
| Ongoing maintenance cost | ⚠️ Medium. The rule set needs adversarial evolution (Unit 42 has already shown that bypasses happen) |

---

## 4. Direction: Phase 0 is the highest-leverage step

### 4.1 Why the corpus study comes first

Snyk's recognition came from auditing 3,984 skills; Socket's came from scanning 60,000
skills; the arXiv GitSkills paper came from a 3.8M-file corpus.
**In this field, the news value of "the first large-scale empirical measurement" far
exceeds that of yet another tool release.**

And it solves four problems at once:
1. **Recognition** — a data report is naturally picked up by HN / Reddit / security press / academic citations
2. **Credibility** — "we scanned 100,000 skills and found that X% have undeclared outbound access" cannot be argued with
3. **Rule validation** — measure precision/recall on a real corpus rather than self-made fixtures
4. **Dataset ownership** — the corpus index itself becomes a citable asset (GitSkills is already indexed by alphaXiv)

### 4.2 The Phase 0 proposal

```text
skillguard scan --corpus <source> --stats --json
```

Producing `docs/CORPUS_REPORT.md`:
- Corpus: stratified sampling from skills.sh / ClawHub / the GitHub tag `agent-skills`
  (target 100,000 skills, **all commit-pinned with recorded digests**, reproducible
  methodology)
- Metrics:
  - the share containing hardcoded secrets
  - the share containing a `download → execute` chain
  - the share containing shell execution / outbound network / sensitive path access
  - **the share with a frontmatter permission declaration (expected < 2% — that gap is the declared-vs-observed market opening)**
  - the share with a LICENSE / the share where the declaration conflicts with the file
  - the detection rules' precision (on 500 hand-annotated samples)
  - the distribution of bypass techniques: base64, zero-width characters, oversized files (Unit 42 has confirmed these work)
- **Honest disclosure**: detection ≠ judgement; include a false-positive analysis

Supporting outputs:
- A public JSON dataset (skill path + digest + finding summary), directly citable by third-party research
- An arXiv preprint (the ecosystem's security posture)
- A technical blog post plus material for a Show HN

**This step needs only the Phase 1 scanner plus a corpus driver mode. Low technical risk,
extremely high return.**

### 4.3 Distribution channels (ordered by effectiveness)

Following Semgrep's path (founded 2017 → open sourced 2020 → about 2M users / 15.3k stars by
2023 → Series D in 2025), **the biggest lever was never the HN post — it was becoming a
default part of the ecosystem** (GitLab 14 adopted Semgrep as its default SAST analyzer).

| Priority | Channel | Concrete action | Why it works |
|---|---|---|---|
| **P0** | **A default part of the ecosystem** | ① a pre-commit hook ② a GitHub Action (zero install, via Code Scanning) ③ a Rust library + C ABI for other tools to embed | Semgrep's core turning point |
| **P0** | **Interoperate rather than replace** | `skillguard import skills-lock.json`; be called by skil-lock / skillmds / registry services | The path of least resistance |
| P1 | **The Phase 0 report** | An arXiv preprint + a technical blog post + a public dataset | The only way to reach the HN front page |
| P1 | **Contributable rules** | A contribution flow pairing rule IDs with fixtures one-to-one (Semgrep's 3,000+ community rules are its key asset) | Rule count is the moat |
| P2 | **Awesome-list presence** | `LLMSecurity/awesome-agent-skills-security`, `mcp-security-project/awesome-agentic-mcp-security`, `baibizhe/Awesome-Skills-Paper` — all actively accept PRs | Long-tail, continuous traffic |
| P2 | **Research collaboration** | Connect with the academic groups behind Skill-Inject / SkillsMP; a citation is the most durable backlink | Academic credibility |
| P2 | **A security-researcher channel** | Invite organisations like Trail of Bits to publish rules; the open-security skills ecosystem is very active | Credibility + rules |
| P3 | Conferences / talks | OWASP Agentic Security, SANS, BSides, ChaosConf | Depth rather than breadth |
| P3 | OpenSSF / foundations | Apply to the Security Tooling group; Tidelift / Sponsors to sustain maintenance | Long-term sustainability |

### 4.4 Realistic expectations for a cold start (the honest version)

The observed distribution of Show HN posts:
- Feature-complete + no audience: ~2 points, 1 comment (the real SecureClaw case)
- Has an audience + states the pain clearly: 100–260 points, 30–65 comments (Tracecat: 264)
- Strong brand backing: higher (SubImage: 135)

**Conclusion: do not post a Show HN before the product is finished.** The right order is
the Phase 0 report (data, a hook) → the Phase 1 tool (something to try) → Phase 2
differentiation → one Launch HN.

---

## 5. Naming and brand (a recommended decision)

| Option | Note | Recommendation |
|---|---|---|
| `skillguard` | Already used by 2 arXiv papers + at least 2 running projects (agentsec.sh, SecureClaw) hold the mindshare. Search results will drown it | 🔴 Not recommended |
| **`skilltrust`** | Semantically accurate (a trust layer), consistent with the project's positioning, clean to search | 🟢 Usable |
| **`skillscope`** | Emphasises "see everything about a skill", and distinguishes itself adequately from skills.sh/awesomeagentskills | 🟢 Usable |
| **`sgt`** (skill guard tool) | Short, easy to type on a CLI | 🟡 Usable but low information |
| **`veriskill` / `skillverify`** | Emphasises verification | 🟡 Usable |

**Recommendation: keep the repository name `SkillGuard` (it is created, pushed, and there
is no sunk cost), but use `skillscope` or `skilltrust` as the product name, and explain the
relationship in the README's first paragraph.**
Or, more decisively: **rename the repository to `skillscope` and note SkillGuard as the old
name in the README.**

This is a decision for you to make; see the questions at the end of this document.

---

## 6. Milestones (reordered)

| Stage | Content | Purpose | Exit condition |
|---|---|---|---|
| **P0** | The corpus scan mode + a 100k-skill empirical report + a public dataset + an arXiv preprint | **Recognition and rule validation** | Rule precision ≥ 0.85 (500 annotated samples); report published |
| P1 | Scanner + 44 rules + SARIF + GH Action + pre-commit + a Rust library | A usable product | Fixtures all green; embedded or adopted by at least 1 external tool |
| P2 | Capability + `adopt` to generate declarations + declared vs observed (report only, no blocking at first) | Differentiation | Precision ≥ 0.8; validated on 30 real skills |
| P3 | The policy engine + blocking + the approval lockfile + `import skills-lock.json` | Landing in a workflow | Zero writes on deny (an assertion test) |
| P4 | Corpus index / a rule registry / research collaboration | The moat | ≥ 20 community rule contributions |
| P5 (optional) | `add` / `install` (only if P1–P3 show clear user demand) | Contesting for an ecosystem slot | — |

**Note: P5 moves from "default" to "optional".** The installer is the largest cost item and
the lowest strategic value.

---

## 7. Go/No-Go decision points

Each stage ends with an explicit stop-loss / pivot condition:

| Checkpoint | Continue if | Pivot/abandon if |
|---|---|---|
| After P0 | The report is covered by ≥ 2 security outlets or gets ≥ 50 points on HN; precision ≥ 0.85 | Nobody notices → **degenerate into a pure CLI tool**, do no brand work, and focus on doing P1 well |
| After P1 | 100+ stars within 30 days; adopted by ≥ 1 external project (embedded/depended on) | No external adoption → prioritise CI/a rule registry over new features |
| After P2 | Precision ≥ 0.8 and users ask to "turn blocking on" | Precision falls short → **keep "report but do not block" permanently** and position the product as an "evidence generator" rather than a gatekeeper. That is still a valuable product (SkillMD's position) |
| Throughout | Maintainer effort ≤ 10 hours/week | Exceeded → contract to P0+P1 (scanner + report) and stop expanding the product |

---

## 8. The final recommendation (one sentence)

> **First produce a data report nobody can ignore, then a scanner everyone can use offline,
> then define the standard for "how to verify a Skill" — and get others to use your standard.**
>
> Do not try to become the install entry point — 7.24M weekly downloads already live there.
> Become **the verification standard** — where today there is one company with a $1B
> valuation, which must be online, and which does not verify declarations.

**Feasibility conclusion: ✅ worth building. The direction needs adjusting: narrow from
"package manager" to "verification layer + standard + data".**

---

## Appendix: data sources

- The Skillful.sh ecosystem report (2026-09-30, aggregating 55 directories)
- arXiv 2608.10906 "GitSkills" (collected 2026-07, 3.8M files / 282k repositories)
- arXiv 2602.08004 (a data-driven analysis of 40,285 skills, 18.5× growth / 20 days)
- arXiv 2603.02176 "AgentSkillOS" (a 200K-scale evaluation)
- arXiv 2605.11418 (metadata-only registry poisoning, an 86% pairwise win rate)
- arXiv 2606.03024 "SkillGuard: A Permission Framework for Agent Skills" (91.0% F1, 56.5% over-declared / 17.4% under-declared)
- arXiv 2605.10990 "Skill Drift Is Contract Violation" (a same-named system)
- USENIX Security 2026 "Do Not Mention This to the User: Detecting and Understanding Malicious Agent Skills in the Wild"
- Cloud Security Alliance research briefs (2026-05 Agent Context Poisoning; 2026-06 Poisoned Skills / ClawHub)
- Koi Security (Oren Yomtov) ClawHub audit 2026-02; Unit 42 tracking 2026-02 to 05
- Snyk Labs "Skill Inspector" and the 2026-02 ecosystem audit; the ToxicSkills naming
- Socket.dev (scanning skills.sh from 2026-02; Series C $60M / $1B, 2026-03)
- The Endor Labs AURI product page (an agentic security platform, policy enforced at the moment of action)
- Check Point Research (Claude Code CVE-2025-59536 / CVE-2026-21852; a Cursor MCP attack chain)
- Anthropic's incident disclosure (2026-07-30, an agent published a malicious PyPI package; 15 real systems ran it)
- StepSecurity, Oligo Security (analyses of the TeamPCP 2026-03 campaign)
- Semgrep's about page / funding history; the Tracecat and SubImage Show HN data points
- Project repositories and documentation: snyk/agent-scan, skillmds/skillmd, agent-contracts/skill-preflight, vercel-labs/skills, skills-lock/skil-lock, skillpkg/spm, NVIDIA/SkillSpector, the crates.io `skill` crate
