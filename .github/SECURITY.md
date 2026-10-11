# Security policy

## Reporting a vulnerability in SkillGuard

SkillGuard is a security tool, so it has an obvious attack surface: the SKILL.md
parser, the dependency parsers, the `sgdir-v1` digest, the policy engine and the
path handling that keeps a walk inside the skill directory. Report a
vulnerability in **SkillGuard itself** privately, through GitHub's private
vulnerability reporting:

**https://github.com/lxbworld/SkillGuard/security/advisories/new**

Do not open a public issue, and do not describe an exploitable parser or path
bug publicly before there is a fix.

Please include the version (or the commit you built from), a minimal
reproduction, and what an attacker gains. An input that makes the scanner panic
is a vulnerability: `docs/THREAT_MODEL.md` §7 promises that no input causes a
panic. We aim to acknowledge a report within **7 days**.

Only the latest release and `main` are supported. Pre-1.0, there are no
backports.

## What is not a vulnerability here

- **A finding about a scanned skill.** That is the tool working, not a bug.
  See below.
- **A heuristic that can be evaded.** Detection is not prevention, and any rule
  set over natural language and scripts can be rephrased around. This is a
  documented limitation (`docs/THREAT_MODEL.md` T1), not a vulnerability.
- **Anything that requires executing the scanned skill.** The scanner never
  executes what it reads, never opens a socket, and never spawns a process other
  than `git` for provenance.

## Reporting a malicious skill

Finding these is the point of the project. Open a normal
[issue](https://github.com/lxbworld/SkillGuard/issues), and **do not paste the
payload**: a rule id, a content digest, a file path and a line number reproduce
almost anything, and this project does not redistribute malware. If a real
skill is actively distributing malware, report it to the registry or host that
serves it as well.

## Disclosure of corpus findings

The same discipline applies to the research in `research/`: a finding goes to
the operator of the affected skill or registry **privately first**, with a
7-day window before anything is public, and no payloads are ever published. The
state of each request is recorded in `research/DISCLOSURE.md`.
