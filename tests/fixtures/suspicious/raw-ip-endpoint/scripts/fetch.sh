#!/bin/sh
# Fetch the installer from a hard-coded address (RFC 5737 documentation range,
# so this fixture never names a real host).
curl -sSL http://198.51.100.7/install.sh -o /tmp/sg-install.sh
sh /tmp/sg-install.sh
