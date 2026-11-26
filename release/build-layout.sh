#!/bin/bash
# Build and verify the signed update layout for one release (PROTOCOL.md §8.1).
#
#   release/build-layout.sh \
#       --version 0.1.0-beta.1 \
#       --artifact client:macos:any:13=target/pkg/Faro-0.1.0-beta.1.pkg \
#       --artifact server:linux:aarch64=dist/faro-server-0.1.0-beta.1-linux-aarch64 \
#       --data model=dist/model/manifest.json \
#       --data blocklist=dist/blocklist/domains.manifest.json \
#       --roots release \
#       --published published/ \
#       --targets-key targets.key.json --timestamp-key timestamp.key.json \
#       --out layout/
#
# --artifact KIND:PLATFORM:ARCH[:MIN_OS]=PATH adds one artifact under the
# target name KIND/PLATFORM/<file name>. Repeat it for each artifact.
#
# --data KIND[:MIN_CLIENT]=MANIFEST adds a model or a blocklist (PROTOCOL.md
# §8.1, "Models and blocklists"): KIND is `model` (a faro_detect::ModelInfo
# manifest) or `blocklist` (a domains-compile manifest), with the file the
# manifest names next to it. Its version is the manifest's, not the
# release's. Before anything is signed, the script checks that the file
# matches the manifest's BLAKE3 (and that a blocklist has no unapproved
# source). It joins the two with `faro-release pack-data` and lists the
# bundle as KIND/any/<name>-<version>-<first channel>.data (`+` in the
# version becomes `_`), platform and arch `any`, and MIN_CLIENT as its
# `min_client` if given. Bundles are byte-for-byte reproducible, so a
# release that ships the same version again finds it already listed. The
# same version with other bytes is refused: bump the version.
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
data=()
while (( $# )); do
    case "$1" in
        --version) version="${2:?}"; shift ;;
        --artifact) artifacts+=("${2:?}"); shift ;;
        --data) data+=("${2:?}"); shift ;;
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
(( ${#artifacts[@]} + ${#data[@]} )) || die "at least one --artifact or --data is required"
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

for spec in "${artifacts[@]+"${artifacts[@]}"}"; do
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

# The first channel names the bundle: a beta-only listing and a later
# stable one of the same version are different entries.
channel_tag="${channels[1]}"
for spec in "${data[@]+"${data[@]}"}"; do
    [[ "$spec" == *=* ]] || die "--data $spec: expected KIND[:MIN_CLIENT]=MANIFEST"
    manifest="${spec#*=}"
    IFS=: read -r kind min_client extra <<< "${spec%%=*}"
    [[ -z "${extra:-}" ]] || die "--data $spec: expected KIND[:MIN_CLIENT]=MANIFEST"
    [[ -f "$manifest" ]] || die "--data $spec: no such manifest"
    case "$kind" in
        model)
            dname="$(jq -er .name "$manifest")" || die "$manifest: no name"
            payload="$(jq -er .file "$manifest")" || die "$manifest: no file"
            want="$(jq -er .blake3 "$manifest")" || die "$manifest: no blake3"
            ;;
        blocklist)
            dname=domains
            payload="$(jq -er .bundle.file "$manifest")" || die "$manifest: no bundle.file"
            want="$(jq -er .bundle.blake3 "$manifest")" || die "$manifest: no bundle.blake3"
            [[ "$(jq -r .unapproved_included "$manifest")" == false ]] ||
                die "$manifest includes unapproved sources; it must never ship"
            ;;
        *) die "--data $spec: KIND is model or blocklist" ;;
    esac
    dversion="$(jq -er .version "$manifest")" || die "$manifest: no version"
    is_semver "$dversion" || die "$manifest: version $dversion is not a semver version"
    [[ "$dname" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "$manifest: name $dname can't be part of a target name"
    [[ "$payload" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "$manifest: $payload is not a plain file name"
    payload="$(dirname "$manifest")/$payload"
    [[ -f "$payload" ]] || die "$manifest names $payload, which is missing"
    got="$("$FARO_RELEASE" describe-target --file "$payload" | jq -er .blake3)"
    [[ "$got" == "b3:$want" ]] || die "$payload has blake3 ${got#b3:}, but $manifest pins $want"
    file="$dname-${dversion//+/_}-$channel_tag.data"
    name="$kind/any/$file"
    echo "==> $name"
    "$FARO_RELEASE" pack-data --manifest "$manifest" --payload "$payload" --out "$work/$file"
    min=()
    [[ -z "${min_client:-}" ]] || min=(--min-client "$min_client")
    "$FARO_RELEASE" add-target --metadata "$work/targets.unsigned.json" --file "$work/$file" \
        --name "$name" --kind "$kind" --platform any --arch any \
        --version "$dversion" "${channels[@]}" "${min[@]+"${min[@]}"}"
    mkdir -p "$out/targets/$kind/any"
    cp "$work/$file" "$out/targets/$name"
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
