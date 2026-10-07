#!/usr/bin/env python3
"""Render a CSV file as a markdown table. Standard library only."""

import csv
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: build.py <input.csv>", file=sys.stderr)
        return 2
    with open(argv[1], newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        return 0
    header, *body = rows
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join(["---"] * len(header)) + "|")
    for row in body:
        print("| " + " | ".join(row) + " |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
