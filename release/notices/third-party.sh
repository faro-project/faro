#!/bin/bash
# Third-party notices for Faro's Rust programs (docs/DEVELOPMENT.md
# "Third-party notices"): every crate a program is built from, from
# Cargo.lock, grouped by licence, with each licence's text as the crates
# ship it.
#
#   release/notices/third-party.sh server OUT   faro-server for Linux
#                                                 (the binaries and the image)
#   release/notices/third-party.sh macos OUT    faro-service and faro-agent
#                                                 (the macOS package)
#   release/notices/third-party.sh --cargo-about-version
#   release/notices/third-party.sh --install-cargo-about
#
# It runs cargo-about, pinned to CARGO_ABOUT_VERSION below.
# --install-cargo-about installs that version unless it is already the one
# on PATH, replacing any other (self-hosted runners keep ~/.cargo/bin
# between runs, where a plain `cargo install` refuses an existing binary):
#
#   cargo install --locked --force cargo-about --version 0.9.3 --features cli
#
# The accepted licences are deny.toml's `[licenses] allow` list, the one
# `cargo deny check` enforces, and a crate whose licence can't be read or
# isn't on it fails the run. Only the crates built for the component's
# targets are listed, without build and dev dependencies. Faro's own
# crates are listed too, under its Apache-2.0 licence.
set -euo pipefail

CARGO_ABOUT_VERSION=0.9.3

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
usage="usage: third-party.sh server|macos OUT"

if [[ "${1:-}" == --cargo-about-version ]]; then
    echo "$CARGO_ABOUT_VERSION"
    exit 0
fi
if [[ "${1:-}" == --install-cargo-about ]]; then
    if [[ "$(cargo about --version 2>/dev/null || true)" == "cargo-about $CARGO_ABOUT_VERSION" ]]; then
        echo "cargo-about $CARGO_ABOUT_VERSION is already installed"
    else
        cargo install --locked --force cargo-about --features cli --version "$CARGO_ABOUT_VERSION"
    fi
    exit 0
fi
component="${1:?$usage}"
out="${2:?$usage}"

case "$component" in
    server)
        title="faro-server"
        targets='"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"'
        # package, features
        runs=("server/Cargo.toml|")
        ;;
    macos)
        title="the Faro package for macOS (faro-service and Faro Agent)"
        targets='"aarch64-apple-darwin", "x86_64-apple-darwin"'
        # build-pkg.sh builds faro-service with the image classifier.
        runs=("crates/faro-service/Cargo.toml|onnx" "crates/faro-agent/Cargo.toml|")
        ;;
    *) echo "$usage" >&2; exit 2 ;;
esac

have="$(cargo about --version 2>/dev/null || true)"
if [[ "$have" != "cargo-about $CARGO_ABOUT_VERSION" ]]; then
    echo "third-party.sh needs cargo-about $CARGO_ABOUT_VERSION (found: ${have:-none}):" >&2
    echo "  cargo install --locked cargo-about --version $CARGO_ABOUT_VERSION --features cli" >&2
    exit 1
fi

# The allowlist, from deny.toml.
allow="$(sed -n '/^\[licenses\]/,/^\[[a-z]/p' "$repo/deny.toml" \
    | sed -n '/^allow = \[/,/^\]/p' | sed 's/#.*//' | grep -o '"[^"]*"' | paste -sd, -)"
[[ -n "$allow" ]] || { echo "cannot read the [licenses] allow list from deny.toml" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/about.toml" <<EOF
accepted = [$allow]
targets = [$targets]
ignore-build-dependencies = true
ignore-dev-dependencies = true
EOF

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -n1)"
{
    echo "Third-party software in $title $version"
    echo
    echo "Faro is free software under the Apache License 2.0. Its programs are"
    echo "built from the Rust crates listed below, generated from Cargo.lock."
    echo "Each licence is shown once, with every crate that uses it, followed by"
    echo "its text as the crates ship it."
} > "$work/out.txt"
for run in "${runs[@]}"; do
    manifest="${run%%|*}"
    features="${run#*|}"
    args=(generate --locked --fail -c "$work/about.toml" -m "$repo/$manifest" -o "$work/part.txt")
    [[ -n "$features" ]] && args+=(--features "$features")
    cargo about "${args[@]}" "$here/about.hbs"
    {
        echo
        echo
        echo "========================================================================"
        echo "$(sed -n 's/^name = "\(.*\)"/\1/p' "$repo/$manifest" | head -n1)"
        echo "========================================================================"
        echo
        cat "$work/part.txt"
    } >> "$work/out.txt"
done
mkdir -p "$(dirname "$out")"
mv "$work/out.txt" "$out"
