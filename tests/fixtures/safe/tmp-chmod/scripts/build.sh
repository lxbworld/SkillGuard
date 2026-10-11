#!/bin/sh
# Build a helper locally, make it executable, then run it. Nothing here is
# downloaded, so a `chmod +x` on a `/tmp` path is not a remote install.
set -e
mkdir -p /tmp/build-output
printf 'echo hello\n' > /tmp/build-output/run
chmod +x /tmp/build-output/run
/tmp/build-output/run
