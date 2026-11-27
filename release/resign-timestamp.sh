#!/bin/bash
# Re-sign the published metadata so clients keep accepting the release
# (PROTOCOL.md §8). Run by .github/workflows/update-timestamp.yml.
#
#   release/resign-timestamp.sh --roots release --published published/ \
#       --timestamp-key timestamp.key.json --out layout/
#   release/resign-timestamp.sh --roots release --published published/ \
#       --timestamp-key timestamp.key.json --renew-targets targets.key.json --out layout/
#
# The first form writes a new timestamp.json into --out, committing to the
# published targets.json, and the roots from release/roots (so a new root is
# published by the next run). It never needs the targets key.
#
# With --renew-targets, if the published targets.json expires within
# FARO_TARGETS_RENEW_DAYS (default 21), it is re-signed first: the same
# entries, the next version and a new expiry (FARO_TARGETS_EXPIRY_DAYS,
# default 42). It goes into --out with a timestamp for it. If it doesn't
# need renewing, nothing is written and --out stays empty.
#
# Either way the result is verified on top of the published documents
# before this returns. The days left on the published targets.json are
# printed, and written to $GITHUB_OUTPUT as targets_days_left when set.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
here="$repo/release"
# shellcheck source=release/lib.sh
. "$here/lib.sh"

roots=""
published=""
targets_key=""
timestamp_key=""
out=""
while (( $# )); do
    case "$1" in
        --roots) roots="${2:?}"; shift ;;
        --published) published="${2:?}"; shift ;;
        --renew-targets) targets_key="${2:?}"; shift ;;
        --timestamp-key) timestamp_key="${2:?}"; shift ;;
        --out) out="${2:?}"; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
for v in roots published timestamp_key out; do
    [[ -n "${!v}" ]] || die "--${v//_/-} is required"
done
[[ -f "$published/timestamp.json" && -f "$published/targets.json" ]] ||
    die "nothing published in $published: there is no release to re-sign yet"
[[ ! -e "$out" ]] || [[ -z "$(ls -A "$out")" ]] || die "$out is not empty"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

root_args "$roots"
published_args "$published"

# The published documents' signatures and consistency, ignoring expiry, to
# read when targets.json expires.
"$FARO_RELEASE" inspect "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]}" > "$work/published.json"
cat "$work/published.json"
targets_expires="$(jq -er .targets.expires_ms "$work/published.json")" ||
    die "cannot read the expiry of the published targets.json"
days_left=$(( (targets_expires - $(now_s) * 1000) / 86400000 ))
echo "the published targets.json expires in $days_left days"
[[ -z "${GITHUB_OUTPUT:-}" ]] || echo "targets_days_left=$days_left" >> "$GITHUB_OUTPUT"

targets="$published/targets.json"
if [[ -n "$targets_key" ]]; then
    if (( days_left >= ${FARO_TARGETS_RENEW_DAYS:-21} )); then
        echo "targets.json doesn't need renewing yet"
        exit 0
    fi
    echo "==> renewing targets.json"
    "$FARO_RELEASE" next-targets "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]}" \
        --expires-ms "$(expires_ms $(( ${FARO_TARGETS_EXPIRY_DAYS:-42} * 24 )))" \
        --out "$work/targets.unsigned.json"
    "$FARO_RELEASE" sign-targets --metadata "$work/targets.unsigned.json" \
        --key "$targets_key" --out "$out/targets.json"
    targets="$out/targets.json"
fi

echo "==> signing the timestamp"
sign_timestamp "$targets" "$timestamp_key" "$out/timestamp.json"
# Roots committed since the last publish go out with this run.
copy_roots "$roots" "$out"

echo "==> verifying"
if ! "$FARO_RELEASE" verify "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]}" \
    --timestamp "$out/timestamp.json" --targets "$targets"; then
    if [[ -z "$targets_key" ]]; then
        echo "If the targets key was just replaced, targets.json must be re-signed with" >&2
        echo "the new one: run with --renew-targets (update-timestamp.yml does this when" >&2
        echo "update-root.json names a targets key that didn't sign targets.json)." >&2
    fi
    exit 1
fi
echo "==> $out"
