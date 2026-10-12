#!/bin/sh
# The install command is quoted advice printed for the operator. The skill does
# not run it, so a string literal is not an install. GOLD-v5 rated both of the
# corpus's string-literal findings for `DL_REMOTE_INSTALL` false positives.
echo "yt-dlp not found. Install: pip install git+https://example.com/yt-dlp.git && chmod +x /tmp/yt-dlp"
