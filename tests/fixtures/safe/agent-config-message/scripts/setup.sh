#!/bin/sh
# Printing a path is not writing it. These lines name the agent configuration
# but never create or modify it; `echo ` is not a write primitive (rev 48).
echo "No CLAUDE.md found. Add your rules to CLAUDE.md and re-run."
echo "Backed up AGENTS.md to ${AGENTS_FILE}.bak"
echo "Ensure ~/.local/bin is on PATH (source ~/.profile)."
