#!/usr/bin/env bash
# Fetch ONNX Runtime for the Android build, checked against pinned SHA-256
# digests (ARCHITECTURE.md §3.5). build-android.sh runs it.
#
#   crates/faro-android/fetch-onnxruntime.sh OUT_DIR
#
# writes
#
#   OUT_DIR/arm64-v8a/libonnxruntime.so     for ORT_LIB_LOCATION
#   OUT_DIR/x86_64/libonnxruntime.so
#   OUT_DIR/notices/onnxruntime-LICENSE.txt
#   OUT_DIR/notices/onnxruntime-ThirdPartyNotices.txt
#
# pyke's prebuilt ONNX Runtime (ort-sys's dist.txt) has no Android build, so
# this is Microsoft's own: the onnxruntime-android AAR on Maven Central, whose
# jni/<abi>/libonnxruntime.so is a shared library with the plain C API that
# `ort` links dynamically (ORT_PREFER_DYNAMIC_LINK). The AAR carries no
# licence files, so they come from the same release's Python wheel on PyPI,
# as in installers/macos/fetch-onnxruntime.sh.
#
# The version must be the one ort-sys was written for: ONNX Runtime 1.22.0
# for ort-sys 2.0.0-rc.10. To move to a new ONNX Runtime, update `ort` in
# crates/faro-detect/Cargo.toml, installers/macos/fetch-onnxruntime.sh,
# installers/windows/fetch-onnxruntime.ps1, and the pins here.
#
# Downloads are cached by digest in FARO_ORT_CACHE (default
# %LOCALAPPDATA%\faro-onnxruntime on Windows, ~/.cache/faro-onnxruntime
# elsewhere) and checked again on every use.
set -euo pipefail

usage="usage: fetch-onnxruntime.sh OUT_DIR"
out="${1:?$usage}"
(( $# == 1 )) || { echo "$usage" >&2; exit 2; }

# ONNX Runtime 1.22.0, as ort-sys 2.0.0-rc.10 pins it. Maven Central's own
# .sha256 for the AAR says the same.
version=1.22.0
aar_url=https://repo1.maven.org/maven2/com/microsoft/onnxruntime/onnxruntime-android/$version/onnxruntime-android-$version.aar
aar_sha256=04a4617a9c797cf49225595e45b5546081cb34c86ac817581141577d3b7dbfe2
abis=(arm64-v8a x86_64)
# The licence files, from onnxruntime 1.22.0's wheel on PyPI.
wheel_url=https://files.pythonhosted.org/packages/67/3c/c99b21646a782b89c33cffd96fdee02a81bc43f0cb651de84d58ec11e30e/onnxruntime-1.22.0-cp310-cp310-macosx_13_0_universal2.whl
wheel_sha256=85d8826cc8054e4d6bf07f779dc742a363c39094015bdad6a08b3c18cfe0ba8c
license_sha256=2f07c72751aed99790b8a4869cf2311df85a860b22ded05fa22803587a48922c
notices_sha256=e9e90971a8e75a9a8ac0c6412e29c1202d079998389915aa485f46c816c3b4cc

fail() { echo "fetch-onnxruntime.sh: $*" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
  sha256() { sha256sum < "$1" | awk '{print $1}'; }
else
  sha256() { shasum -a 256 < "$1" | awk '{print $1}'; }
fi

if [ -n "${FARO_ORT_CACHE:-}" ]; then
  cache=$FARO_ORT_CACHE
elif [ -n "${LOCALAPPDATA:-}" ]; then
  cache=$LOCALAPPDATA/faro-onnxruntime
else
  cache=$HOME/.cache/faro-onnxruntime
fi
mkdir -p "$out" "$cache"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Print the path of the cached download of URL, fetching it if the cache
# lacks it or has a file with another digest. Refuses anything that isn't WANT.
fetch() {
  local url=$1 want=$2 cached="$cache/sha256-$2"
  if [ ! -f "$cached" ] || [ "$(sha256 "$cached")" != "$want" ]; then
    echo "    downloading $url" >&2
    curl -fsSL --proto '=https' --retry 3 -o "$cached.$$.part" "$url" || { rm -f "$cached.$$.part"; fail "download failed: $url"; }
    local got
    got=$(sha256 "$cached.$$.part")
    if [ "$got" != "$want" ]; then
      rm -f "$cached.$$.part"
      fail "$url: sha256 $got, want $want"
    fi
    mv -f "$cached.$$.part" "$cached"
  fi
  echo "$cached"
}

echo "==> ONNX Runtime $version for Android"
aar=$(fetch "$aar_url" "$aar_sha256")
wheel=$(fetch "$wheel_url" "$wheel_sha256")

rm -rf "${out:?}/notices"
for abi in "${abis[@]}"; do
  rm -rf "${out:?}/$abi"
  mkdir -p "$out/$abi"
  unzip -p "$aar" "jni/$abi/libonnxruntime.so" > "$out/$abi/libonnxruntime.so" ||
    fail "the AAR has no jni/$abi/libonnxruntime.so"
  [ -s "$out/$abi/libonnxruntime.so" ] || fail "jni/$abi/libonnxruntime.so is empty"
  # An ELF shared library.
  [ "$(head -c 4 "$out/$abi/libonnxruntime.so" | od -An -c | tr -d ' ')" = '177ELF' ] ||
    fail "jni/$abi/libonnxruntime.so is not an ELF file"
done

mkdir -p "$out/notices"
unzip -p "$wheel" onnxruntime/LICENSE > "$out/notices/onnxruntime-LICENSE.txt"
unzip -p "$wheel" onnxruntime/ThirdPartyNotices.txt > "$out/notices/onnxruntime-ThirdPartyNotices.txt"
[ "$(sha256 "$out/notices/onnxruntime-LICENSE.txt")" = "$license_sha256" ] || fail "ONNX Runtime LICENSE changed"
[ "$(sha256 "$out/notices/onnxruntime-ThirdPartyNotices.txt")" = "$notices_sha256" ] || fail "ThirdPartyNotices.txt changed"
echo "    ${abis[*]}, licence and notices in $out"
