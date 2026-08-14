#!/usr/bin/env bash
set -euo pipefail

KEYLOG_FILE="${SSLKEYLOGFILE:-/home/kali/sslkeys.log}"
BROWSER="${1:-}"

mkdir -p "$(dirname "$KEYLOG_FILE")"
touch "$KEYLOG_FILE"

export SSLKEYLOGFILE="$KEYLOG_FILE"

if [[ -n "$BROWSER" ]]; then
  shift
  exec "$BROWSER" "$@"
fi

if command -v firefox >/dev/null 2>&1; then
  exec firefox "$@"
elif command -v chromium >/dev/null 2>&1; then
  exec chromium "$@"
elif command -v chromium-browser >/dev/null 2>&1; then
  exec chromium-browser "$@"
elif command -v google-chrome >/dev/null 2>&1; then
  exec google-chrome "$@"
else
  echo "No supported browser found (firefox/chromium/chromium-browser/google-chrome)." >&2
  exit 1
fi
