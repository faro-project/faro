#!/bin/bash
# Build Faro's OpenNSFW models from Yahoo's original files (ARCHITECTURE.md
# §3.5, docs/DEVELOPMENT.md "The image model").
#
#   crates/faro-detect/models/opennsfw/build.sh OUT_DIR
#   crates/faro-detect/models/opennsfw/build.sh --parity OUT_DIR
#
# Writes OUT_DIR/opennsfw-int8.onnx (the model the package ships) with
# manifest.json, opennsfw-fp32.onnx with manifest-fp32.json (for
# benchmarking), and NOTICE.txt (the attribution and BSD-2-Clause text).
#
# 1. Installs the pinned tools (requirements.txt, checked by SHA-256) into
#    a fresh virtual environment. Needs CPython 3.9: the Command Line
#    Tools' /usr/bin/python3, or FARO_PYTHON.
# 2. Downloads Yahoo's deploy.prototxt, resnet_50_1by2_nsfw.caffemodel and
#    LICENSE.md from github.com/yahoo/open_nsfw at a fixed commit, and
#    refuses any whose SHA-256 or BLAKE3 differs from the pins below.
# 3. Converts and quantizes them with convert.py, and refuses a model whose
#    BLAKE3 differs from its manifest's. The models are never committed.
# 4. Checks LICENSE.md against the manifests' license_text and writes the
#    notice (notice.py).
# 5. With --parity, also checks the models against the Caffe original
#    (parity.py, with OpenCV as the reference).
#
# Downloads and models are cached by digest in FARO_MODEL_CACHE (default
# ~/Library/Caches/faro-models) and checked again on every use, so a
# repeat build only installs the tools.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
parity=0
out=""
while (( $# )); do
    case "$1" in
        --parity) parity=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown argument: $1" >&2; exit 2 ;;
        *) [[ -z "$out" ]] || { echo "one OUT_DIR only" >&2; exit 2; }; out="$1" ;;
    esac
    shift
done
[[ -n "$out" ]] || { echo "usage: build.sh [--parity] OUT_DIR" >&2; exit 2; }

# Yahoo's repository is archived; this is its last commit.
commit=a4e13931465f4380742545932657eeea0a10aa48
base="https://raw.githubusercontent.com/yahoo/open_nsfw/$commit"
#       path in the repository                    sha256                                                            blake3
sources=(
    "nsfw_model/deploy.prototxt                   a359e2d7b23abca938bb52580acf578c1b78870263fea814afa294fb4f315a4b b97851e2cfa587d96f0d9f26bb39d9c03cc09860a7a3a8fd1f6e98d96cd7ab3d"
    "nsfw_model/resnet_50_1by2_nsfw.caffemodel    74b7c0374425c2b324f73b134f8a7254eab9bbddc9e452a22d934b8c17015ad2 1fd6ab5bd5197143cc3be5fca37fcb3bb3ace3b3e3e44e5687486ac6e73a4866"
    "LICENSE.md                                   d5767a135a80d5122186098ba0204ef17b7ef869aae128eb76c825e91304c269 6ba6344cf7672925cccb7e7b4fab0abced7c98d13fa87c9240b13db59aa68417"
)

if [[ "$(uname -s)" == Darwin ]]; then
    python="${FARO_PYTHON:-/usr/bin/python3}"
    cache="${FARO_MODEL_CACHE:-$HOME/Library/Caches/faro-models}"
else
    python="${FARO_PYTHON:-python3}"
    cache="${FARO_MODEL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/faro-models}"
fi
mkdir -p "$out" "$cache"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "build.sh: $*" >&2; exit 1; }

echo "==> installing the pinned tools"
"$python" -I -c 'import sys; sys.exit(sys.version_info[:2] != (3, 9))' \
    || fail "$python is not CPython 3.9 (the tools are pinned for it); set FARO_PYTHON"
"$python" -I -m venv "$work/venv"
py=("$work/venv/bin/python" -I)
reqs=(-r "$here/requirements.txt")
(( parity )) && reqs+=(-r "$here/requirements-parity.txt")
"${py[@]}" -m pip install --quiet --disable-pip-version-check --require-hashes --only-binary=:all: "${reqs[@]}"

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
b3() { "${py[@]}" -c 'import sys, blake3; print(blake3.blake3(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
field() { "${py[@]}" -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
# Copy a cached file into the work directory and check it there, so what
# is checked is what is used. Prints nothing; fails if it doesn't match.
from_cache() {
    local key="$1" dest="$2" want_b3="$3"
    [[ -f "$cache/$key" ]] || return 1
    cp "$cache/$key" "$dest"
    [[ "$(b3 "$dest")" == "$want_b3" ]] || { rm -f "$dest"; return 1; }
}
to_cache() {
    cp "$1" "$cache/.$2.$$"
    mv "$cache/.$2.$$" "$cache/$2"
}

# Yahoo's files. LICENSE.md is always needed; the Caffe files only to
# convert or to check parity.
mkdir -p "$work/src"
fetch() {
    local rel="$1" want_sha="$2" want_b3="$3"
    local dest="$work/src/$(basename "$rel")"
    if ! from_cache "sha256-$want_sha" "$dest" "$want_b3"; then
        echo "    downloading $rel"
        curl -fsSL --proto '=https' --retry 3 -o "$dest" "$base/$rel"
        local got
        got="$(sha256 "$dest")"
        [[ "$got" == "$want_sha" ]] || fail "$rel: sha256 $got, want $want_sha"
        got="$(b3 "$dest")"
        [[ "$got" == "$want_b3" ]] || fail "$rel: blake3 $got, want $want_b3"
        to_cache "$dest" "sha256-$want_sha"
    fi
    [[ "$(sha256 "$dest")" == "$want_sha" ]] || fail "$rel: sha256 changed"
}
fetch_all() {
    local want="$1" line rel sha b
    for line in "${sources[@]}"; do
        read -r rel sha b <<< "$line"
        [[ "$want" == all || "$rel" == "$want" ]] && fetch "$rel" "$sha" "$b"
    done
    return 0
}
echo "==> Yahoo's files (yahoo/open_nsfw@${commit:0:12})"
fetch_all LICENSE.md

# The models, from the cache if they're there, else converted now.
mkdir -p "$work/models"
manifests=("$here/manifest.json" "$here/manifest-fp32.json")
missing=0
for m in "${manifests[@]}"; do
    file="$(field "$m" file)"
    want="$(field "$m" blake3)"
    from_cache "blake3-$want.onnx" "$work/models/$file" "$want" || missing=1
done
if (( missing || parity )); then
    fetch_all all
fi
if (( missing )); then
    echo "==> converting"
    "${py[@]}" "$here/convert.py" --prototxt "$work/src/deploy.prototxt" \
        --caffemodel "$work/src/resnet_50_1by2_nsfw.caffemodel" --out "$work/conv"
    for m in "${manifests[@]}"; do
        file="$(field "$m" file)"
        want="$(field "$m" blake3)"
        got="$(b3 "$work/conv/$file")"
        [[ "$got" == "$want" ]] || fail "convert.py made $file with blake3 $got, but $(basename "$m") pins $want.
The tools or this machine give different bytes; see docs/DEVELOPMENT.md \"The image model\"."
        cp "$work/conv/$file" "$work/models/$file"
        to_cache "$work/models/$file" "blake3-$want.onnx"
    done
fi

echo "==> notice"
"${py[@]}" "$here/notice.py" --license "$work/src/LICENSE.md" --out "$work/models/NOTICE.txt" "${manifests[@]}"

if (( parity )); then
    echo "==> parity with the Caffe original"
    "${py[@]}" "$here/parity.py" --prototxt "$work/src/deploy.prototxt" \
        --caffemodel "$work/src/resnet_50_1by2_nsfw.caffemodel" --models "$work/models"
fi

for m in "${manifests[@]}"; do
    install -m 644 "$m" "$out/$(basename "$m")"
    install -m 644 "$work/models/$(field "$m" file)" "$out/$(field "$m" file)"
done
install -m 644 "$work/models/NOTICE.txt" "$out/NOTICE.txt"
echo "==> $out"
for m in "${manifests[@]}"; do
    echo "    $(field "$m" file)  blake3 $(field "$m" blake3)"
done
