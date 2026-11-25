#!/bin/bash
# Fetch ONNX Runtime for the macOS package, checked against pinned SHA-256
# digests (ARCHITECTURE.md §3.5). build-pkg.sh runs it.
#
#   installers/macos/fetch-onnxruntime.sh OUT_DIR TRIPLE...
#
# For each Rust target TRIPLE (aarch64-apple-darwin, x86_64-apple-darwin)
# it unpacks the static library into OUT_DIR/TRIPLE/onnxruntime/lib, for
# ORT_LIB_LOCATION. It also writes ONNX Runtime's licence and third-party
# notices into OUT_DIR/notices: the static builds carry none, so they are
# taken from the same release's Python wheel on PyPI.
#
# The static builds are the ones the `ort` crate's build script would
# download itself (ort-sys's dist.txt; build-pkg.sh checks that these pins
# match it). Fetching them here means every package build checks the digest
# of what it links, rather than trusting ort-sys's download cache, and that
# a system ONNX Runtime found by pkg-config is never linked instead.
#
# With ORT_SYS_DIST (the path of ort-sys's dist.txt) it also checks that
# its pins are ort-sys's. To move to a new ONNX Runtime, update `ort` in
# crates/faro-detect/Cargo.toml, then copy the new URLs and digests from
# its ort-sys's dist.txt here, with the new wheel's licence files.
#
# Downloads are cached by digest in FARO_ORT_CACHE (default
# ~/Library/Caches/faro-onnxruntime) and checked again on every use.
set -euo pipefail

usage="usage: fetch-onnxruntime.sh OUT_DIR TRIPLE..."
out="${1:?$usage}"
shift
(( $# )) || { echo "$usage" >&2; exit 2; }

# ONNX Runtime 1.22.0, as ort-sys 2.0.0-rc.10 pins it.
version=1.22.0
static_url() { echo "https://cdn.pyke.io/0/pyke:ort-rs/ms@$version/$1.tgz"; }
static_sha256() {
    case "$1" in
        aarch64-apple-darwin) echo 00fbfd6f08bac2a4e28c66723af900d58d1b4b1c73efba6290637cd3019883d5 ;;
        x86_64-apple-darwin) echo e0538783248bbb77d2e97556134b8cc47cfc35ac3d762067d51eaf8355c0f48e ;;
        *) return 1 ;;
    esac
}
# The licence files, from onnxruntime 1.22.0's wheel on PyPI.
wheel_url=https://files.pythonhosted.org/packages/67/3c/c99b21646a782b89c33cffd96fdee02a81bc43f0cb651de84d58ec11e30e/onnxruntime-1.22.0-cp310-cp310-macosx_13_0_universal2.whl
wheel_sha256=85d8826cc8054e4d6bf07f779dc742a363c39094015bdad6a08b3c18cfe0ba8c
license_sha256=2f07c72751aed99790b8a4869cf2311df85a860b22ded05fa22803587a48922c
notices_sha256=e9e90971a8e75a9a8ac0c6412e29c1202d079998389915aa485f46c816c3b4cc

cache="${FARO_ORT_CACHE:-$HOME/Library/Caches/faro-onnxruntime}"
mkdir -p "$out" "$cache"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "fetch-onnxruntime.sh: $*" >&2; exit 1; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# Copy url's file into the work directory from the cache, or download it,
# and check its digest there. Prints the work copy's path.
fetch() {
    local url="$1" want="$2" name="$3"
    local dest="$work/$name"
    if [[ -f "$cache/sha256-$want" ]]; then
        cp "$cache/sha256-$want" "$dest"
    fi
    if [[ ! -f "$dest" || "$(sha256 "$dest")" != "$want" ]]; then
        echo "    downloading $url" >&2
        curl -fsSL --proto '=https' --retry 3 -o "$dest" "$url"
        local got
        got="$(sha256 "$dest")"
        [[ "$got" == "$want" ]] || fail "$url: sha256 $got, want $want"
        cp "$dest" "$cache/.sha256-$want.$$"
        mv "$cache/.sha256-$want.$$" "$cache/sha256-$want"
    fi
    echo "$dest"
}

for t in "$@"; do
    want="$(static_sha256 "$t")" || fail "no pinned ONNX Runtime for $t"
    # The pins must be ort-sys's (its dist.txt: feature set, target, URL,
    # SHA-256), or the Rust bindings may not match the library.
    if [[ -n "${ORT_SYS_DIST:-}" ]]; then
        read -r dist_url dist_sha < <(awk -v t="$t" '$1 == "none" && $2 == t { print $3, $4 }' "$ORT_SYS_DIST")
        [[ "${dist_url:-}" == "$(static_url "$t")" ]] \
            || fail "$t: ort-sys downloads ${dist_url:-nothing}, but this script pins $(static_url "$t")"
        [[ "$(echo "${dist_sha:-}" | tr 'A-F' 'a-f')" == "$want" ]] \
            || fail "$t: ort-sys pins sha256 ${dist_sha:-nothing}, but this script pins $want"
    fi
    echo "==> ONNX Runtime $version for $t"
    tgz="$(fetch "$(static_url "$t")" "$want" "$t.tgz")"
    rm -rf "${out:?}/$t"
    mkdir -p "$out/$t"
    tar -xzf "$tgz" -C "$out/$t"
    lib="$out/$t/onnxruntime/lib/libonnxruntime.a"
    [[ -f "$lib" ]] || fail "$t: no onnxruntime/lib/libonnxruntime.a in the archive"
    arch="${t%%-*}"
    [[ "$arch" == aarch64 ]] && arch=arm64
    lipo -info "$lib" | grep -q "architecture: $arch\$" || fail "$lib is not $arch: $(lipo -info "$lib")"
done

echo "==> ONNX Runtime $version licence and notices"
whl="$(fetch "$wheel_url" "$wheel_sha256" onnxruntime.whl)"
mkdir -p "$out/notices"
unzip -p "$whl" onnxruntime/LICENSE > "$out/notices/onnxruntime-LICENSE.txt"
unzip -p "$whl" onnxruntime/ThirdPartyNotices.txt > "$out/notices/onnxruntime-ThirdPartyNotices.txt"
[[ "$(sha256 "$out/notices/onnxruntime-LICENSE.txt")" == "$license_sha256" ]] || fail "ONNX Runtime LICENSE changed"
[[ "$(sha256 "$out/notices/onnxruntime-ThirdPartyNotices.txt")" == "$notices_sha256" ]] || fail "ThirdPartyNotices.txt changed"
echo "$version" > "$out/version"
