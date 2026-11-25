#!/bin/bash
# Check a built package without installing it: the payload has every file
# at its fixed location with root ownership, the agent app carries the
# right bundle identifier, the install scripts are present, and the
# installer only installs for the whole computer. Every program must be
# universal (arm64 + x86_64) and built for the minimum macOS, unless
# `--arch` names the one architecture of a local single-architecture build.
#
# The image model must be there with its manifest, and the notices with
# the model's BSD-2-Clause text and attribution and ONNX Runtime's licence
# and third-party notices. faro-service must link ONNX Runtime statically,
# and the slice for this Mac's architecture must load the model (licence,
# attribution and digest checks) and score three solid colours within
# MODEL_TOLERANCE of Yahoo's original Caffe model.
#
#   installers/macos/check-pkg.sh target/pkg/Faro-<version>[-dev].pkg
#   installers/macos/check-pkg.sh --arch arm64 target/pkg/Faro-<version>-dev.pkg
set -euo pipefail

usage="usage: check-pkg.sh [--arch universal|arm64|x86_64] PKG"
arch=universal
case "${1:-}" in
    --arch) arch="${2:-}"; shift 2 || { echo "$usage" >&2; exit 2; } ;;
    --arch=*) arch="${1#--arch=}"; shift ;;
esac
pkg="${1:?$usage}"
case "$arch" in
    universal) want_archs=arm64,x86_64 ;;
    arm64|x86_64) want_archs="$arch" ;;
    *) echo "$usage" >&2; exit 2 ;;
esac
# The oldest macOS Faro supports (ARCHITECTURE.md §3.3).
min_os=13.0
# p(nsfw) of Yahoo's Caffe model for solid black, white and grey (128), as
# crates/faro-detect/models/opennsfw/parity.py computes them with OpenCV.
# A solid colour is the same classifier input whatever the resize, so the
# packaged int8 model must agree within its parity tolerance.
model_reference=("solid-black 0.066799" "solid-white 0.014106" "solid-grey 0.197584")
MODEL_TOLERANCE=0.05

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "check-pkg: $*" >&2; exit 1; }

pkgutil --expand "$pkg" "$work/x"
component="$work/x/faro-component.pkg"
[[ -d "$component" ]] || fail "no faro-component.pkg inside"

dist="$work/x/Distribution"
grep -q 'enable_localSystem="true"' "$dist" || fail "must install for the whole computer"
grep -q 'enable_currentUserHome="false"' "$dist" || fail "must not offer a per-user install"
host_archs="$(sed -n 's/.*hostArchitectures="\([^"]*\)".*/\1/p' "$dist")"
[[ "$host_archs" == "$want_archs" ]] || fail "hostArchitectures is \"$host_archs\" (want $want_archs)"
[[ "$(sed -n 's/.*<os-version min="\([0-9.]*\)".*/\1/p' "$dist")" == "$min_os" ]] \
    || fail "the installer must require macOS $min_os"

for s in preinstall postinstall lib.sh; do
    [[ -f "$component/Scripts/$s" ]] || fail "missing script $s"
done

# The payload, with owner and mode, as Installer will lay it down.
mkdir "$work/payload"
(cd "$work/payload" && gzip -dc "$component/Payload" | cpio -i --quiet 2>/dev/null)
listing="$(cd "$work/x" && lsbom -p mugf "$component/Bom")"
expect() {
    local path="$1" mode="$2"
    local line
    line="$(echo "$listing" | awk -F'\t' -v p="./$path" '$4 == p')" || true
    [[ -n "$line" ]] || fail "payload lacks /$path"
    [[ "$(echo "$line" | awk -F'\t' '{print $2"/"$3}')" == "0/0" ]] || fail "/$path is not root:wheel: $line"
    [[ "$(echo "$line" | awk -F'\t' '{print $1}')" == "$mode" ]] || fail "/$path mode: $line (want $mode)"
}
# Extended attributes travel as AppleDouble records and are restored as
# attributes on install. None may become stray `._*` files, and none may be
# quarantine or similar (Gatekeeper would then question the agent). Only
# `com.apple.provenance`, which macOS adds to files built by some sandboxed
# tools and cannot be cleared, is tolerated.
if find "$work/payload" -name '._*' | grep -q .; then
    fail "payload unpacks to AppleDouble (._*) files"
fi
other="$(xattr -r "$work/payload" 2>/dev/null | awk -F': ' '{print $NF}' | sort -u | grep -vx 'com.apple.provenance' || true)"
[[ -z "$other" ]] || fail "payload carries extended attributes: $other"
expect "Library/Faro/bin/faro-service" 100755
expect "Library/Faro/bin/faro-uninstall" 100755
expect "Library/Faro/Faro Agent.app/Contents/MacOS/faro-agent" 100755
expect "Library/Faro/Faro Agent.app/Contents/Info.plist" 100644
expect "Library/Faro/service.toml.default" 100644
expect "Library/LaunchDaemons/org.faro.service.plist" 100644
expect "Library/LaunchAgents/org.faro.agent.plist" 100644
model_dir="Library/Faro/models/opennsfw"
expect "$model_dir/manifest.json" 100644
expect "$model_dir/opennsfw-int8.onnx" 100644
expect "Library/Faro/notices/opennsfw.txt" 100644
expect "Library/Faro/notices/onnxruntime-LICENSE.txt" 100644
expect "Library/Faro/notices/onnxruntime-ThirdPartyNotices.txt" 100644
# What the licences ask to travel with the binaries.
notices="$work/payload/Library/Faro/notices"
has() { grep -qF -- "$2" "$notices/$1" || fail "notices/$1 lacks \"$2\""; }
has opennsfw.txt "Copyright 2016, Yahoo Inc."
has opennsfw.txt "BSD-2-Clause"
has opennsfw.txt "Redistributions in binary form must reproduce the above copyright notice"
has opennsfw.txt "https://github.com/yahoo/open_nsfw/"
has onnxruntime-LICENSE.txt "Copyright (c) Microsoft Corporation"
has onnxruntime-LICENSE.txt "Permission is hereby granted, free of charge"
has onnxruntime-ThirdPartyNotices.txt "THIRD PARTY SOFTWARE NOTICES AND INFORMATION"
# The update root of trust: required in a release package (without it the
# service never updates), optional in a development one.
update_root="$work/payload/Library/Faro/update-root.json"
if [[ -e "$update_root" ]]; then
    expect "Library/Faro/update-root.json" 100644
    grep -q '"application/vnd.faro.root+json"' "$update_root" || fail "update-root.json is not a signed root document"
elif [[ "$(basename "$pkg")" != *-dev.pkg ]]; then
    fail "a release package must ship /Library/Faro/update-root.json"
fi

bash -n "$work/payload/Library/Faro/bin/faro-uninstall" || fail "faro-uninstall does not parse"

# Every program in the payload has a slice for each architecture. Our own
# programs are built for exactly the minimum macOS (MACOSX_DEPLOYMENT_TARGET);
# anything else in the payload may be built for an older one, never a newer.
not_newer() { [[ "$(printf '%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" == "$1" ]]; }
machos=0
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q '^Mach-O' || continue
    machos=$((machos + 1))
    rel="${f#"$work/payload/"}"
    got="$(lipo -archs "$f" | tr ' ' '\n' | sort | paste -sd, -)"
    [[ "$got" == "$want_archs" ]] || fail "/$rel has architectures $got (want $want_archs)"
    for a in ${want_archs//,/ }; do
        minos="$(vtool -arch "$a" -show-build "$f" | awk '$1 == "minos" { print $2; exit }')"
        [[ -n "$minos" ]] || fail "/$rel ($a) has no minimum macOS version"
        case "$rel" in
            Library/Faro/bin/faro-service | */Contents/MacOS/faro-agent)
                [[ "$minos" == "$min_os" ]] || fail "/$rel ($a) is built for macOS $minos (want $min_os)" ;;
            *)
                not_newer "$minos" "$min_os" || fail "/$rel ($a) needs macOS $minos, newer than $min_os" ;;
        esac
    done
done < <(find "$work/payload" -type f -print0)
(( machos >= 2 )) || fail "the payload has $machos Mach-O files (want faro-service and faro-agent)"

# ONNX Runtime is linked into faro-service, never loaded from a dylib.
service="$work/payload/Library/Faro/bin/faro-service"
if otool -L "$service" | grep -qi onnxruntime; then
    fail "faro-service loads ONNX Runtime dynamically: $(otool -L "$service" | grep -i onnxruntime)"
fi
# The model, through the packaged service, on this Mac's architecture.
host_arch="$(uname -m)"
if [[ ",$want_archs," == *",$host_arch,"* ]]; then
    check="$("$service" model-check --manifest "$work/payload/$model_dir/manifest.json" --runs 5)" \
        || fail "faro-service ($host_arch) cannot use the packaged model"
    echo "$check"
    for ref in "${model_reference[@]}"; do
        read -r frame want <<< "$ref"
        got="$(echo "$check" | awk -v f="$frame" '$1 == f { for (i = 2; i < NF; i++) if ($i == "nsfw") print $(i + 1) }')"
        [[ -n "$got" ]] || fail "model-check printed no nsfw score for $frame"
        awk -v a="$got" -v b="$want" -v t="$MODEL_TOLERANCE" 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d <= t) }' \
            || fail "$frame: the packaged model gives p(nsfw) $got, the original $want (tolerance $MODEL_TOLERANCE)"
    done
else
    echo "check-pkg: no $host_arch slice to run; the model check is skipped"
fi

info="$work/payload/Library/Faro/Faro Agent.app/Contents/Info.plist"
[[ "$(plutil -extract CFBundleIdentifier raw "$info")" == org.faro.agent ]] || fail "agent bundle id"
[[ "$(plutil -extract LSMinimumSystemVersion raw "$info")" == "$min_os" ]] || fail "agent LSMinimumSystemVersion (want $min_os)"
[[ "$(plutil -extract LimitLoadToSessionType raw "$work/payload/Library/LaunchAgents/org.faro.agent.plist")" == Aqua ]] \
    || fail "the agent must load in every GUI session"
codesign --verify --strict "$work/payload/Library/Faro/Faro Agent.app" || fail "agent signature"
[[ "$(codesign -dv "$work/payload/Library/Faro/Faro Agent.app" 2>&1 | sed -n 's/^Identifier=//p')" == org.faro.agent ]] \
    || fail "agent signing identifier"

echo "check-pkg: $pkg is well-formed"
