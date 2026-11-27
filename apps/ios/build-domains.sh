#!/bin/bash
# Builds the domain category list the packet tunnel ships with (docs/IOS.md
# §7.2), and its notice, from the pinned sources in
# crates/faro-detect/domains/sources.toml (downloaded unless
# target/domains/sources already has them):
#
#   apps/ios/Generated/Domains/domains.bin            the list
#   apps/ios/Generated/Domains/domains.manifest.json  its manifest, which the
#                                                     tunnel loads it through
#   apps/ios/Generated/Notices/domains.txt            its notice, for the
#                                                     Licences screen
#
#   apps/ios/build-domains.sh
#
# The list and its notice come from the same build, so they always match.
# build-notices.sh runs this too. Run it before `xcodegen generate`. It uses
# the host's Rust toolchain (plain `cargo`). A release build must include
# the list; without it the tunnel blocks only the always-blocked names and
# the member's own list, and logs why.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
domains="$here/Generated/Domains"
notices="$here/Generated/Notices"
mkdir -p "$domains" "$notices"

config="$repo/crates/faro-detect/domains/sources.toml"
compile=(cargo run --manifest-path "$repo/Cargo.toml" --locked --quiet
    -p faro-detect --example domains-compile --)
"${compile[@]}" fetch --config "$config" --sources-dir "$repo/target/domains/sources"
"${compile[@]}" build --config "$config" --sources-dir "$repo/target/domains/sources" \
    --out "$domains/domains.bin"
"${compile[@]}" notice --manifest "$domains/domains.manifest.json" --out "$notices/domains.txt"

echo "wrote $domains and $notices/domains.txt"
