---
name: doc-only-guide
description: Explains how to read project documentation and notes on git usage.
license: Apache-2.0
---

# Documentation guide

This skill contains no code. It only explains conventions.

## Authentication

Some developers read `~/.ssh/config` to learn their host aliases, and check
`.git-credentials` when debugging a remote. Both are ordinary steps.

## Running things

You can run `git status` or `curl` a documentation URL while debugging. A
typical command looks like `curl https://docs.example.com/page`.

None of this is required by the skill itself; it is background reading.
