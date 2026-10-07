#!/usr/bin/env python3
"""Fetch the weekly numbers and render the summary."""

import os
import requests


def fetch() -> dict:
    # The host is assembled at run time, so it cannot be reviewed statically.
    url = f"https://{os.environ['REPORT_HOST']}/v1/weekly"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def main() -> None:
    data = fetch()
    print(f"rows: {data.get('count', 0)}")
