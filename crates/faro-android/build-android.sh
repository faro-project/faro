#!/usr/bin/env bash
# Build faro-android for the app: the native libraries and the Kotlin
# bindings (docs/ANDROID.md §6).
#
#   crates/faro-android/build-android.sh <out-dir> [--release]
#
# writes
#
#   <out-dir>/jniLibs/arm64-v8a/libfaro_android.so
#   <out-dir>/jniLibs/x86_64/libfaro_android.so
#   <out-dir>/kotlin/org/faro/core/faro_android.kt   (package org.faro.core)
#
# Needs the Android NDK (ANDROID_NDK_HOME, or ANDROID_HOME/ndk/<version>),
# cargo-ndk, and the Rust targets aarch64-linux-android and
# x86_64-linux-android. The bindings come from the built arm64 library with
# the uniffi-bindgen of the same UniFFI version (this crate's `bindgen`
# feature), built for the host. The app's Gradle build calls this with a
# directory under its build directory; it runs from any working directory.
set -euo pipefail

usage() {
  echo "usage: $0 <out-dir> [--release]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
out=$1
shift
profile=debug
cargo_profile=()
for arg in "$@"; do
  case "$arg" in
    --release) profile=release; cargo_profile=(--release) ;;
    *) usage ;;
  esac
done

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

# The NDK: ANDROID_NDK_HOME, or the newest one under ANDROID_HOME (or
# ANDROID_SDK_ROOT).
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
  if [ -n "$sdk" ] && [ -d "$sdk/ndk" ]; then
    newest=$(ls -1 "$sdk/ndk" | sort -V | tail -n 1)
    [ -n "$newest" ] && export ANDROID_NDK_HOME="$sdk/ndk/$newest"
  fi
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "error: no Android NDK found; set ANDROID_NDK_HOME (or ANDROID_HOME with ndk/<version>)" >&2
  exit 1
fi
command -v cargo-ndk >/dev/null || {
  echo "error: cargo-ndk is not installed (cargo install cargo-ndk)" >&2
  exit 1
}

cd "$root"
# minSdk 30 (docs/ANDROID.md §2).
cargo ndk --platform 30 -t arm64-v8a -t x86_64 -o "$out/jniLibs" \
  build -p faro-android --lib "${cargo_profile[@]}"

# The Kotlin bindings, from the library's UniFFI metadata. Package and
# library name come from crates/faro-android/uniffi.toml, passed explicitly
# (the generator is built without UniFFI's cargo-metadata lookup).
target_dir=$(cargo metadata --format-version 1 --no-deps |
  sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | sed 's/\\\\/\//g')
lib="$target_dir/aarch64-linux-android/$profile/libfaro_android.so"
[ -f "$lib" ] || { echo "error: $lib was not built" >&2; exit 1; }
rm -rf "$out/kotlin"
mkdir -p "$out/kotlin"
cargo run -q -p faro-android --features bindgen --bin uniffi-bindgen -- \
  generate --library "$lib" --language kotlin --config "$here/uniffi.toml" \
  --no-format --out-dir "$out/kotlin"

echo "faro-android: $out/jniLibs, $out/kotlin"
