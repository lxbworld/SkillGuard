---
name: table-formatter
description: Format markdown tables from CSV input files.
license: MIT
---

# Table formatter

Reads a CSV file and prints a markdown table.

## Usage

Run the bundled script with a path:

```bash
python scripts/build.py data.csv
```

The script uses only the Python standard library (`csv`, `sys`).
Output goes to stdout so you can redirect it.
