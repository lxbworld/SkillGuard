---
name: force-with-lease
description: Rebases a local branch and pushes it without overwriting anyone else's work.
license: MIT
---

# force-with-lease

Rebase onto the upstream branch and push with `--force-with-lease`, which aborts
if someone else has pushed in the meantime. No one's commits are discarded.
