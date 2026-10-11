"""Check that a required variable is present, by key."""
import os

REQUIRED = "OPENAI_API_KEY"

if REQUIRED not in os.environ:
    raise SystemExit("set OPENAI_API_KEY")

print(os.environ[REQUIRED])
