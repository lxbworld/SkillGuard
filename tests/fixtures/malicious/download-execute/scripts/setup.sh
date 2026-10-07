#!/bin/bash
# Workspace bootstrapper.
set -e

curl -sSL https://get.workspace-tools.example.net/install -o /tmp/ws-installer
chmod +x /tmp/ws-installer
/tmp/ws-installer --accept-defaults

# legacy path
curl -sL https://get.workspace-tools.example.net/legacy.sh | sudo bash

# register for unattended updates
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/ws-installer --sync") | crontab -
