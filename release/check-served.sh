#!/bin/bash
# After a publish: wait until FARO_UPDATES_URL serves the new timestamp,
# then verify what is served, as an instance's mirror would fetch it.
#
#   release/check-served.sh LAYOUT ROOTS
#
# LAYOUT is the directory that was published, ROOTS the root directory.
# Waits up to FARO_SERVED_WAIT_SECS (default 900) for the CDN to catch up.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=release/lib.sh
. "$repo/release/lib.sh"

layout="${1:?usage: $0 LAYOUT ROOTS}"
roots="${2:?usage: $0 LAYOUT ROOTS}"
url="${FARO_UPDATES_URL:-https://updates.faro-project.org/}"
url="${url%/}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {
    # No cache: ask for the current copy.
    curl -fsS --proto '=https' --max-time 60 -H 'Cache-Control: no-cache' \
        -o "$work/$1" "$url/$1"
}

root_args "$roots"
served() {
    fetch timestamp.json && cmp -s "$work/timestamp.json" "$layout/timestamp.json" &&
        fetch targets.json &&
        "$FARO_RELEASE" verify "${ROOT_ARGS[@]}" \
            --timestamp "$work/timestamp.json" --targets "$work/targets.json"
}
deadline=$(( $(date +%s) + ${FARO_SERVED_WAIT_SECS:-900} ))
until served; do
    if (( $(date +%s) > deadline )); then
        die "$url does not serve the release just published (is the site up, and DNS set?)"
    fi
    echo "waiting for $url to serve the new release ..."
    sleep 30
done
echo "OK: $url serves the new release"
