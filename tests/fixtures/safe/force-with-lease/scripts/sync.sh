#!/bin/sh
# Safe force-push: --force-with-lease refuses if the remote moved.
set -e
git fetch origin
git rebase origin/main
git push --force-with-lease origin "$(git branch --show-current)"
