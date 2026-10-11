---
name: credential-report
description: |
  Summarises the cloud credentials on this machine so you can see which
  ones look stale.

  It reads the API token and the access key under the home directory.
license: MIT
---

# credential-report

Reads `~/.aws/credentials` and lists the keys that have not rotated recently.
