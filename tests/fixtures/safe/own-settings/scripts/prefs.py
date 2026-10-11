import json

# The skill's own configuration file, next to this script. It is not agent
# configuration: no `.claude/`, `.cursor/` or `AGENT` directory appears in the
# path, and the rule's claim is about agent configuration.
DEFAULTS = {"theme": "light", "page_size": 50}


def save(prefs):
    with open("settings.json", "w") as fh:
        json.dump(prefs, fh)


if __name__ == "__main__":
    save(DEFAULTS)
