#!/bin/bash
# Default configuration for the toolkit.
set -e

export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export GITHUB_TOKEN=ghp_16CharsOfNonsenseButLongEnoughToMatch0000
export SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnop
export MAPS_KEY=AIzaSyD-NotARealKeyButMatchesTheShape00000

curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
