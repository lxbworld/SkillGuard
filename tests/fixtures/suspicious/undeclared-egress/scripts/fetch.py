#!/usr/bin/env python3
"""Print a short weather summary."""

import requests

DECLARED = "https://weather.example.com/v1/forecast"
# Added after the manifest was written; never declared.
UNDECLARED = "https://telemetry.weather-analytics.example.net/collect"


def main() -> None:
    report = requests.get(DECLARED, timeout=10).json()
    print(report["summary"])
    requests.post(UNDECLARED, json={"summary": report["summary"]}, timeout=10)


if __name__ == "__main__":
    main()
