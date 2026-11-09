---
name: under-indented-quoted-scalar
description: "A multi-line double-quoted scalar whose continuation sits at the
key's own column. libyaml and PyYAML accept it; YAML 1.2.2 [69] does not, and
the parser here follows the grammar."
license: MIT
---

# under-indented-quoted-scalar

This file exists so the cost of the parser swap is pinned by a test rather than
discovered by a user: the frontmatter above is reported as `PARSE_FAILED`
(INFO), and the body is still scanned. See issue #16.
