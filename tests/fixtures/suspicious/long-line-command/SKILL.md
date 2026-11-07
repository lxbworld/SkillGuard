---
name: long-line-command
description: A minified installer with the download-and-execute chain on the only line, past the display cap
license: MIT
---

# long-line-command

The installer in `scripts/install.js` is minified onto a single line, and the
`curl … | bash` chain sits past the 200-character display cap. A report that
prints the head of the line cannot show the reader what it matched, which is the
defect measured in issue #10.
