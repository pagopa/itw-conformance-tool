#!/usr/bin/env bash
#
# Presentation wallet hook for the conformance CI job.
#
# The local conformance runner ("itwct test presentation") starts the Relying
# Party + Trust Anchor, generates an OpenID4VP presentation-request deep link,
# and copies that deep link to the system clipboard so a human tester can open
# it with the wallet under test. On Linux the runner copies it by piping the URI
# into the first available clipboard command (wl-copy, then xclip, then xsel).
#
# CI has no clipboard and no human, so this script is installed on PATH under
# those clipboard command names. When the runner "copies" the deep link, this
# hook instead receives it on stdin and launches wct as the wallet under test,
# pointing it at that exact URI. wct is started in the background and the hook
# returns immediately (exit 0) so the runner treats the copy as successful and
# proceeds to wait for the presentation it will now observe.
#
# It therefore fires exactly once per generated deep link, at the moment the
# runner is ready to observe a presentation.
#
# Any command-line arguments (e.g. xclip's "-selection clipboard") are ignored;
# the payload is always read from stdin.
set -euo pipefail

WCT_DIR="${WCT_DIR:-/tmp/wct}"
WCT_LOG="${WCT_LOG:-/tmp/wct-presentation.log}"
WCT_PID_FILE="${WCT_PID_FILE:-/tmp/wct.pid}"
WALLET_VERSION="${WALLET_VERSION:-V1_3}"

presentation_uri="$(cat)"

if [ -z "$presentation_uri" ]; then
  echo "[wallet-hook] received empty clipboard payload; not launching wct" >&2
  exit 0
fi

printf '%s\n' "$presentation_uri" > /tmp/presentation-uri.txt
echo "[wallet-hook] launching wct for presentation URI: ${presentation_uri}"

# Background wct as the wallet under test, detaching its stdio so it keeps
# running after this hook returns. The runner then observes the presentation
# against the Relying Party.
(
  cd "$WCT_DIR"
  exec ./bin/wct test:presentation \
    --unsafe-tls \
    --tests happy \
    --presentation-authorize-uri "$presentation_uri" \
    --wallet-version "$WALLET_VERSION"
) > "$WCT_LOG" 2>&1 < /dev/null &

echo $! > "$WCT_PID_FILE"
