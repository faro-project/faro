#!/bin/bash
# Puts the project's update root of trust where the app bundles it
# (docs/IOS.md §7.2, §14), as the macOS package installs
# /Library/Faro/update-root.json:
#
#   apps/ios/Generated/Update/update-root.json
#
#   FARO_UPDATE_ROOT=path/to/1.root.json apps/ios/build-update-root.sh
#
# The root is FARO_UPDATE_ROOT if set, otherwise release/update-root.json
# (docs/KEY-CEREMONY.md, "Shipping root 1") if it exists. The app verifies
# domain list updates against it, never against anything the instance
# serves (invariant 5). Without a root the file isn't written, and the app
# checks no updates, as a desktop dev build without FARO_UPDATE_ROOT;
# FARO_REQUIRE_UPDATE_ROOT=1 (set it for a release build) makes that an
# error instead. build-rust.sh runs this. Run it before `xcodegen generate`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$here/Generated/Update"
rm -rf "$out"

root="${FARO_UPDATE_ROOT:-}"
if [[ -z "$root" && -f "$repo/release/update-root.json" ]]; then
    root="$repo/release/update-root.json"
fi
if [[ -z "$root" ]]; then
    if [[ "${FARO_REQUIRE_UPDATE_ROOT:-}" == 1 ]]; then
        echo "no update root: set FARO_UPDATE_ROOT or commit release/update-root.json (docs/KEY-CEREMONY.md)" >&2
        exit 1
    fi
    echo "no update root: this build will not check for domain list updates" >&2
    exit 0
fi
[[ -f "$root" ]] || { echo "FARO_UPDATE_ROOT: no such file $root" >&2; exit 1; }
mkdir -p "$out"
install -m 644 "$root" "$out/update-root.json"
echo "wrote $out/update-root.json"
