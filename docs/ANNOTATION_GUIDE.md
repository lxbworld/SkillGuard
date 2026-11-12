# Annotation guide

For a person who has agreed to spend an hour labelling findings. You do not need
to know the rules, the scanner, or security. You need to read one line and answer
one question: **is the rule's claim true of this line?**

## What you are given

A CSV with a fixed header. Each row is one finding:

| column | what it is |
|---|---|
| `finding_id` | already filled in; do not edit, it is how the row is matched back |
| `rule_id` | the rule that fired |
| `file` | where it fired, relative to the skill root |
| `line_start`, `line_end` | the line numbers; usually equal |
| `evidence` | **the line itself**, trimmed. This is what you judge |
| `label` | **you fill this in** |
| `confidence` | **you fill this in** |
| `rationale` | **you fill this in** — a short phrase is enough |
| `reviewer` | **your name**. Required: an import without it is rejected |
| `reviewed_at` | today's date, `YYYY-MM-DD` |

The `rule_id` tells you which claim to check. Each rule's claim is its own
sentence, listed in `docs/RULES.md` under "what it catches". Read it, then decide
whether the `evidence` line is an instance of it.

**Do not open the linked file.** The scanner only shows you the matched line and
its location; the question is whether *that line* is what the rule says it is. If
judging it properly needs more context, that is what `AMBIGUOUS` is for.

## The four labels

### `TP` — the rule is right

The line really is an instance of the claim.

> `rule_id: NET_HTTP_CLIENT`, claim "an HTTP client library is invoked"
> `evidence: requests.get(url)`
> → **TP**. That is an HTTP client invocation.

### `FP` — the rule is wrong

The line is not an instance of the claim.

> `rule_id: PI_CONCEALMENT`, claim "an instruction to hide behaviour from the user"
> `evidence: Products marked as such are never told to the user.`
> → **TP**, it does instruct concealment.
>
> `rule_id: PI_CONCEALMENT`
> `evidence: Detects skills that hide behaviour from the user.`
> → **FP**. That is a description of the *detector*, not an instruction.

### `AMBIGUOUS` — you cannot tell from what you see

Use this whenever guessing would be inventing information. It is not a cop-out and
it is not counted against the rule.

> `rule_id: DL_UNTRUSTED_DOMAIN`, claim "a low-reputation TLD or a raw IP is contacted"
> `evidence: ENDPOINT = os.environ["API_HOST"] + "/v1"`
> → **AMBIGUOUS**. Whether a low-reputation host is contacted depends on a value
> this line does not contain.

### `NOT_APPLICABLE` — the rule does not apply here

Different from `FP`. The text really is what the rule says it is, but the rule's
scope excludes this place. The canonical case: an action rule matching inside a
comment or a docstring that *documents* the action.

> `rule_id: SHELL_EXEC`, claim "the skill invokes an interpreter"
> `evidence: # Run: python3 setup.py install`
> → **NOT_APPLICABLE**. It is a comment. The skill's text names the command; the
> file does not run it.

If the rule's claim is about **presence** — a hardcoded credential, a zero-width
character, an embedded image, a licence term — then a comment is still a valid
place to find it, and `NOT_APPLICABLE` does not apply.

## The one distinction that decides most rows

Every action rule has this question behind it: **is this text doing the thing, or
talking about the thing?**

| doing it (→ TP) | talking about it (→ FP or N/A) |
|---|---|
| a command in a `SKILL.md` body — the agent is meant to run it | the same command quoted in a "never do this" warning |
| a fenced code block in a skill's own instructions | the same block in `docs/` or `references/` |
| `subprocess.run("rm -rf /tmp/x")` | `# remove the build directory` |
| `curl … \| bash` as a shell line | `Usage: curl … \| bash` inside a docstring |

A `SKILL.md` body is special and it is worth being explicit about it: **that text
is the instruction an agent follows.** A command in it counts, even inside a
fenced block. Only a passage that *talks about* the command ("attacks use `rm -rf
/`") is a mention.

This distinction is not hypothetical. It is the single largest source of
disagreement in this project's own labelling rounds: GOLD-v9 failed its agreement
gate at κ 0.593 because this sentence was missing from the annotator instructions,
and adding it moved the same two models on the same rows to κ 0.779.

## Confidence

| | meaning |
|---|---|
| `HIGH` | you would defend this label to the rule's author without re-reading |
| `MEDIUM` | you are fairly sure; the default |
| `LOW` | you had to make a judgement call |

`confidence` does not change whether a row counts. It lets a later round see
whether a disagreement was a coin flip or a real disagreement about the rule's
meaning — which are very different findings about the rule.

## Rules of the job

1. **Judge only the claim.** Not whether the rule is useful, well-named, or
   correctly severe. Not whether the skill is trustworthy overall.
2. **Judge the line you are shown.** If you need more of the file, that is
   `AMBIGUOUS`.
3. **Do not look at the other annotator's file**, and do not discuss rows before
   both files are complete. The whole value of the round is that the two label
   sets are independent.
4. **Do not "fix" a row by editing `evidence` or `line_start`.** If those look
   wrong, that is a finding about the scanner, and it belongs in an issue, not in
   a quietly edited CSV.
5. **Leaving a row completely blank is fine.** It means "not reviewed". It is
   skipped on import, not guessed at. Better a blank than a guess.
6. **A rule is allowed to be wrong.** The point of the exercise is to find out
   which ones are. Nobody is being graded, and a high `FP` rate is a useful result,
   not a failure.

## When you are done

```bash
skillguard gold import <your file>.csv --out research/gold/HUMAN-v1.jsonl
skillguard gold stats research/gold/HUMAN-v1.jsonl
```

`gold import` will refuse the file if `reviewer` is blank on any filled row, and
will name the row and the column. Fix and re-run; nothing is written until the
whole file parses.

## Time budget

95 rows (`--per-stratum 3`, one row per skill and rule) takes about 40 minutes at
a steady pace — roughly 25 seconds a row. If a row takes longer than a minute, it
is usually `AMBIGUOUS`, and that is the right answer.
