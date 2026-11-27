#!/bin/bash
# Builds faro-mobile (the iOS core, docs/IOS.md §13) for the device and the
# Simulator, generates its Swift bindings with UniFFI and packages
# FaroCore.xcframework. Run it before `xcodegen generate`.
#
#   apps/ios/build-rust.sh
#
# Outputs, all git-ignored:
#   apps/ios/FaroCore.xcframework         the static library for both targets,
#                                         with the C header and module map
#   apps/ios/Generated/FaroCore/*.swift   the Swift bindings (project.yml
#                                         compiles them into Faro and FaroTunnel)
#
# Toolchain. The iOS targets (aarch64-apple-ios, aarch64-apple-ios-sim) must
# be installed for the Rust toolchain used:
#   * If plain `cargo` has them (CI after dtolnay/rust-toolchain with
#     `targets:`), it is used.
#   * Otherwise the script looks for rustup (on PATH, or Homebrew's keg-only
#     one in /opt/homebrew/opt/rustup/bin) and runs `cargo +stable`.
#     Install them with `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
#   FARO_RUST_TOOLCHAIN (for example "1.90.0") replaces "stable" there.
#
# uniffi-bindgen is apps/ios/uniffi-bindgen, a tiny crate pinned to the same
# UniFFI version as faro-mobile, which the script checks against Cargo.lock.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$repo"

# Keep in step with the deployment target in project.yml.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
targets=(aarch64-apple-ios aarch64-apple-ios-sim)

has_targets() {
    local t dir
    local -a plus=()
    [[ -n "${1:-}" ]] && plus=("$1")
    for t in "${targets[@]}"; do
        dir="$(rustc ${plus[@]+"${plus[@]}"} --target "$t" --print target-libdir 2>/dev/null || true)"
        [[ -n "$dir" && -d "$dir" ]] || return 1
    done
}

cargo_cmd=(cargo)
rustc_plus=""
if has_targets; then
    :
else
    [[ -d /opt/homebrew/opt/rustup/bin ]] && PATH="/opt/homebrew/opt/rustup/bin:$PATH"
    if command -v rustup >/dev/null 2>&1; then
        tc="${FARO_RUST_TOOLCHAIN:-stable}"
        cargo_cmd=(cargo "+$tc")
        rustc_plus="+$tc"
        if ! has_targets "$rustc_plus"; then
            echo "the $tc toolchain lacks the iOS targets; run:" >&2
            echo "  rustup target add --toolchain $tc ${targets[*]}" >&2
            exit 1
        fi
    else
        echo "no Rust toolchain with the iOS targets (${targets[*]}) found." >&2
        echo "Install rustup and run: rustup target add ${targets[*]}" >&2
        exit 1
    fi
fi
echo "using: ${cargo_cmd[*]}"

# The bindgen must match faro-mobile's UniFFI exactly, or the generated
# Swift and the library disagree about the scaffolding.
lock_version() { awk '/^name = "uniffi"$/ {getline; gsub(/[^0-9.]/, "", $0); print; exit}' "$1"; }
v_core="$(lock_version "$repo/Cargo.lock")"
v_bindgen="$(lock_version "$here/uniffi-bindgen/Cargo.lock")"
if [[ -z "$v_core" || "$v_core" != "$v_bindgen" ]]; then
    echo "UniFFI version mismatch: Cargo.lock has '$v_core', apps/ios/uniffi-bindgen has '$v_bindgen'." >&2
    echo "Change both together (the \`uniffi\` requirement in apps/ios/uniffi-bindgen/Cargo.toml)." >&2
    exit 1
fi

# FARO_DEV=1 builds a development core: a dev_thresholds.json in the app group
# may then lower the burst thresholds (docs/DEVELOPMENT.md, "lower only").
# Never set it for a build that monitors a real person.
features=()
if [[ "${FARO_DEV:-}" == "1" ]]; then
    features=(--features dev)
    echo "DEVELOPMENT CORE: dev_thresholds.json can lower the burst thresholds"
fi

for t in "${targets[@]}"; do
    "${cargo_cmd[@]}" build --release --locked -p faro-mobile ${features[@]+"${features[@]}"} --target "$t"
done

"${cargo_cmd[@]}" build --release --manifest-path "$here/uniffi-bindgen/Cargo.toml" --locked
bindgen="$here/uniffi-bindgen/target/release/faro-uniffi-bindgen"

gen="$here/Generated/FaroCore"
rm -rf "$gen"
mkdir -p "$gen"
"$bindgen" generate --library "$repo/target/aarch64-apple-ios/release/libfaro_mobile.a" \
    --language swift --out-dir "$gen"

# The XCFramework carries the header and module map (module faro_mobileFFI,
# which the generated Swift imports); the Swift file itself is compiled into
# the targets that call the core.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
args=()
for t in "${targets[@]}"; do
    headers="$work/headers-$t"
    mkdir -p "$headers"
    cp "$gen/faro_mobileFFI.h" "$headers/"
    cp "$gen/faro_mobileFFI.modulemap" "$headers/module.modulemap"
    args+=(-library "$repo/target/$t/release/libfaro_mobile.a" -headers "$headers")
done
rm -rf "$here/FaroCore.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$here/FaroCore.xcframework"

echo "built $here/FaroCore.xcframework and $gen"
