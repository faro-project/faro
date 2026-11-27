#!/bin/bash
# Makes the licence texts the iOS app shows on its Licences screen
# (docs/DEVELOPMENT.md "Third-party notices"), into apps/ios/Generated/Notices,
# which project.yml bundles as resources:
#
#   third-party.txt   the Rust crates in faro-mobile's tree
#                     (release/notices/third-party.sh ios, needs cargo-about)
#   domains.txt       the domain list's notice, from the pinned sources in
#                     crates/faro-detect/domains/sources.toml (downloads them
#                     unless target/domains/sources already has them)
#
#   apps/ios/build-notices.sh
#
# Run it before `xcodegen generate`. It uses the host's Rust toolchain
# (plain `cargo`), not the iOS one. Release builds must include both files;
# a development build can leave them out and the screen says so.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$here/Generated/Notices"
mkdir -p "$out"

"$repo/release/notices/third-party.sh" ios "$out/third-party.txt"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
config="$repo/crates/faro-detect/domains/sources.toml"
compile=(cargo run --manifest-path "$repo/Cargo.toml" --locked --quiet
    -p faro-detect --example domains-compile --)
"${compile[@]}" fetch --config "$config" --sources-dir "$repo/target/domains/sources"
"${compile[@]}" build --config "$config" --sources-dir "$repo/target/domains/sources" \
    --out "$work/domains.bin"
"${compile[@]}" notice --manifest "$work/domains.manifest.json" --out "$out/domains.txt"

echo "wrote $out/third-party.txt and $out/domains.txt"
