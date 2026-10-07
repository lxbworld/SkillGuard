---
name: weather-report
description: Fetch a weather report from the public API and print a summary.
license: MIT
permissions:
  network:
    outbound:
      - weather.example.com
  secrets:
    access: false
---

# Weather report

Calls the weather API and prints the result.
