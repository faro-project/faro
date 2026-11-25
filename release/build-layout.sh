#!/bin/bash
# Build and verify the signed update layout for one release (PROTOCOL.md §8.1).
#
#   release/build-layout.sh \
#       --version 0.1.0-beta.1 \
#       --artifact client:macos:any:13=target/pkg/Faro-0.1.0-beta.1.pkg \
#       --artifact server:linux:aarch64=dist/faro-server-0.1.0-beta.1-linux-aarch64 \
#       --roots release \
#       --published published/ \
#       --targets-key targets.key.json --timestamp-key timestamp.key.json \
#       --out layout/
#
# --artifact KIND:PLATFORM:ARCH[:MIN_OS]=PATH adds one artifact under the
# target name KIND/PLATFORM/<file name>. Repeat it for each artifact.
# --roots is a directory laid out like release/: update-root.json (the root
# that packages ship) and roots/<n>.json for every root from 2 on.
# --published is a directory with the timestamp.json and targets.json now at
# the publishing location (release/publish-layout.sh pull). Leave it empty
# for the first release. Every entry it lists is carried over.
#
# Channels come from the version: a pre-release (0.1.0-beta.1) goes to
# `beta` only; a release (0.1.0) goes to `stable` and `beta`.
#
# The output directory gets:
#   targets.json  timestamp.json  roots/<n>.json  targets/<name>
# Older artifacts are not copied: they are already at the publishing
# location, and publishing only ever adds files.
#
# Before it returns, the whole set is checked with `faro-release verify`
# the way an up-to-date client would see it, including every new artifact.
#
# Environment:
#   FARO_RELEASE                 the faro-release binary
#                                (default target/release/examples/faro-release)
#   FARO_TARGETS_EXPIRY_DAYS     default 42
#   FARO_TIMESTAMP_EXPIRY_HOURS  default 24
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
here="$repo/release"
# shellcheck source=release/lib.sh
. "$here/lib.sh"

version=""
roots=""
published=""
targets_key=""
timestamp_key=""
out=""
artifacts=()
while (( $# )); do
    case "$1" in
        --version) version="${2:?}"; shift ;;
        --artifact) artifacts+=("${2:?}"); shift ;;
        --roots) roots="${2:?}"; shift ;;
        --published) published="${2:?}"; shift ;;
        --targets-key) targets_key="${2:?}"; shift ;;
        --timestamp-key) timestamp_key="${2:?}"; shift ;;
        --out) out="${2:?}"; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
for v in version roots published targets_key timestamp_key out; do
    [[ -n "${!v}" ]] || die "--${v//_/-} is required"
done
(( ${#artifacts[@]} )) || die "at least one --artifact is required"
is_semver "$version" || die "--version $version is not a semver version"

channels=(--channel beta)
if ! is_prerelease "$version"; then
    channels=(--channel stable --channel beta)
fi

[[ ! -e "$out" ]] || [[ -z "$(ls -A "$out")" ]] || die "$out is not empty"
mkdir -p "$out/targets"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

root_args "$roots"
published_args "$published"

echo "==> targets.json for $version (${channels[*]})"
"$FARO_RELEASE" next-targets "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]+"${PUBLISHED_ARGS[@]}"}" \
    --expires-ms "$(expires_ms $(( ${FARO_TARGETS_EXPIRY_DAYS:-42} * 24 )))" \
    --out "$work/targets.unsigned.json"

for spec in "${artifacts[@]}"; do
    [[ "$spec" == *=* ]] || die "--artifact $spec: expected KIND:PLATFORM:ARCH[:MIN_OS]=PATH"
    path="${spec#*=}"
    IFS=: read -r kind platform arch min_os extra <<< "${spec%%=*}"
    [[ -n "$kind" && -n "$platform" && -n "$arch" && -z "${extra:-}" ]] ||
        die "--artifact $spec: expected KIND:PLATFORM:ARCH[:MIN_OS]=PATH"
    [[ -f "$path" ]] || die "--artifact $spec: no such file"
    name="$kind/$platform/$(basename "$path")"
    min=()
    [[ -z "${min_os:-}" ]] || min=(--min-os "$min_os")
    "$FARO_RELEASE" add-target --metadata "$work/targets.unsigned.json" --file "$path" \
        --name "$name" --kind "$kind" --platform "$platform" --arch "$arch" \
        --version "$version" "${channels[@]}" "${min[@]+"${min[@]}"}"
    mkdir -p "$out/targets/$(dirname "$name")"
    cp "$path" "$out/targets/$name"
done

echo "==> signing"
"$FARO_RELEASE" sign-targets --metadata "$work/targets.unsigned.json" \
    --key "$targets_key" --out "$out/targets.json"
sign_timestamp "$out/targets.json" "$timestamp_key" "$out/timestamp.json"
copy_roots "$roots" "$out"

echo "==> verifying"
"$FARO_RELEASE" verify "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]+"${PUBLISHED_ARGS[@]}"}" \
    --timestamp "$out/timestamp.json" --targets "$out/targets.json" \
    --artifacts "$out/targets"
echo "==> $out"
