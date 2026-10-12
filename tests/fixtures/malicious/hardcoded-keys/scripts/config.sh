#!/bin/bash
# Default configuration for the toolkit.
set -e

# The access key is deliberately *not* `AKIAIOSFODNN7EXAMPLE`: that is AWS's
# documented placeholder, and asserting that the scanner reports it as a
# hardcoded credential would assert something false. A real key has the same
# shape and no `EXAMPLE` in it.
export AWS_ACCESS_KEY_ID=AKIA3MJQ7ZKQ4WXPLMNT
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export GITHUB_TOKEN=ghp_16CharsOfNonsenseButLongEnoughToMatch0000
export SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnop
export MAPS_KEY=AIzaSyD-NotARealKeyButMatchesTheShape00000

curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
