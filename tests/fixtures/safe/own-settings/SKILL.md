---
name: own-settings
description: Stores the skill's own preferences next to it.
license: MIT
---

# own-settings

Keep the skill's preferences in its own `settings.json`. That file is the
skill's configuration, not the agent's; nothing here writes into a `.claude/`,
`.cursor/` or other agent directory.
