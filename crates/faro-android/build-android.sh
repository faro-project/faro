#!/usr/bin/env bash
# Build faro-android for the app: the native libraries and the Kotlin
# bindings (docs/ANDROID.md §6).
#
#   crates/faro-android/build-android.sh <out-dir> [--release] [--no-onnx] [--dev]
#
# writes
#
#   <out-dir>/jniLibs/arm64-v8a/libfaro_android.so
#   <out-dir>/jniLibs/arm64-v8a/libonnxruntime.so
#   <out-dir>/jniLibs/x86_64/libfaro_android.so
#   <out-dir>/jniLibs/x86_64/libonnxruntime.so
#   <out-dir>/notices/onnxruntime-*.txt          (ONNX Runtime's licence)
#   <out-dir>/kotlin/org/faro/core/faro_android.kt   (package org.faro.core)
#
# The core is built with the `onnx` feature (the image classifier), linked
# dynamically to Microsoft's ONNX Runtime for Android, which
# fetch-onnxruntime.sh downloads and checks; libonnxruntime.so ships next to
# libfaro_android.so. --no-onnx builds without both: frames are then rated
# from context only.
#
# Needs the Android NDK (ANDROID_NDK_HOME, or ANDROID_HOME/ndk/<version>),
# cargo-ndk, and the Rust targets aarch64-linux-android and
# x86_64-linux-android. The bindings come from the built arm64 library with
# the uniffi-bindgen of the same UniFFI version (this crate's `bindgen`
# feature), built for the host. The app's Gradle build calls this with a
# directory under its build directory; it runs from any working directory.
set -euo pipefail

usage() {
  echo "usage: $0 <out-dir> [--release] [--no-onnx] [--dev]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
out=$1
shift
profile=debug
cargo_profile=()
onnx=1
dev=0
for arg in "$@"; do
  case "$arg" in
    --release) profile=release; cargo_profile=(--release) ;;
    --no-onnx) onnx=0 ;;
    # The `dev` feature: lowered detection thresholds from
    # <data_dir>/dev-thresholds.toml. Never in a release build.
    --dev) dev=1 ;;
    *) usage ;;
  esac
done
if [ "$dev" = 1 ] && [ "$profile" = release ]; then
  echo "build-android.sh: --dev is for development builds, not --release" >&2
  exit 2
fi

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
abis=(arm64-v8a x86_64)

# Stale libraries from an earlier build of the other kind must not ship.
rm -rf "$out/jniLibs" "$out/notices"

# ONNX Runtime, one library per ABI.
ort="$out/onnxruntime"
if [ "$onnx" = 1 ]; then
  "$here/fetch-onnxruntime.sh" "$ort"
  mkdir -p "$out/notices"
  cp "$ort"/notices/*.txt "$out/notices/"
fi

# cargo, rustc and the linker are native programs: on Windows (Git Bash) they
# need C:/... and not /c/... (`pwd -W`; elsewhere plain `pwd`). Git Bash
# converts such arguments and variables itself, unless MSYS_NO_PATHCONV is set.
native() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }
out_native=$(native "$out")

# One cargo-ndk run per ABI, because ort-sys links the ONNX Runtime library
# named by ORT_LIB_LOCATION, which differs by ABI. Any other ORT_* setting
# is cleared (as installers/windows/build-msi.ps1 does) so a stray one can't
# make it download or link another build; ORT_CXX_STDLIB is empty because
# the AAR's library carries its own C++ runtime (it needs only libc, libm,
# libdl and liblog), so libc++_shared.so is not needed.
# minSdk 30 (docs/ANDROID.md §2).
for abi in "${abis[@]}"; do
  (
    for v in $(compgen -e | grep "^ORT_" || true); do unset "$v"; done
    features=()
    if [ "$onnx" = 1 ]; then
      export ORT_LIB_LOCATION="$out_native/onnxruntime/$abi"
      export ORT_PREFER_DYNAMIC_LINK=1
      export ORT_SKIP_DOWNLOAD=1
      export ORT_CXX_STDLIB=
      features=(--features onnx)
    fi
    if [ "$dev" = 1 ]; then
      features+=(--features dev)
    fi
    cargo ndk --platform 30 -t "$abi" -o "$out_native/jniLibs" \
      build -p faro-android --lib ${features[@]+"${features[@]}"} ${cargo_profile[@]+"${cargo_profile[@]}"}
  )
  if [ "$onnx" = 1 ]; then
    cp "$ort/$abi/libonnxruntime.so" "$out/jniLibs/$abi/libonnxruntime.so"
  fi
done

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
  generate --library "$lib" --language kotlin --config "$(native "$here")/uniffi.toml" \
  --no-format --out-dir "$out_native/kotlin"

echo "faro-android: $out/jniLibs, $out/kotlin"
