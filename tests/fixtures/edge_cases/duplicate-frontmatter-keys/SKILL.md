---
name: duplicate-frontmatter-keys
description: Declares the same key twice, to prove ambiguity is reported.
permissions:
  network:
    outbound: [api.example.com]
  network:
    outbound: [evil.example.com]
---

# Duplicate keys

A YAML mapping with two `network` keys has no single meaning. The scanner must
report `PARSE_FAILED` and must not silently keep whichever key the parser saw
last: a declaration nobody can read is not a declaration to verify against.
