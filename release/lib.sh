# Shared helpers for the release scripts. Sourced, not run.
# shellcheck shell=bash
# ROOT_ARGS and PUBLISHED_ARGS are read by the scripts that source this.
# shellcheck disable=SC2034

: "${FARO_RELEASE:=$repo/target/release/examples/faro-release}"
[[ -x "$FARO_RELEASE" ]] || {
    echo "no faro-release at $FARO_RELEASE: run" >&2
    echo "  cargo build --release --locked -p faro-update --example faro-release" >&2
    exit 1
}

die() {
    echo "error: $*" >&2
    exit 1
}

is_semver() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

# A pre-release has a `-` part before any `+` build part: 0.1.0-beta.1.
is_prerelease() {
    [[ "${1%%+*}" == *-* ]]
}

now_s() {
    date -u +%s
}

# Unix milliseconds, $1 hours from now.
expires_ms() {
    echo $(( ($(now_s) + $1 * 3600) * 1000 ))
}

# Decode base64url without padding (as envelopes carry their payload).
b64url_decode() {
    local s
    s="$(tr '_-' '/+')"
    while (( ${#s} % 4 )); do s="$s="; done
    printf '%s' "$s" | base64 -d 2>/dev/null || printf '%s' "$s" | base64 -D
}

# The version inside a root envelope, read without verifying it: it only
# picks which later roots to apply, and faro-release verifies them all.
root_version() {
    jq -r .payload "$1" | b64url_decode | jq -er .version
}

# The root of trust lives in a directory DIR laid out like release/
# (docs/KEY-CEREMONY.md, "Shipping root 1"):
#   DIR/update-root.json   the newest root: new packages and images ship it
#   DIR/roots/1.json       root 1, kept so the chain can be walked from the
#                          start (optional; never published)
#   DIR/roots/<n>.json     every root from 2 on, published as roots/<n>.json
#
# root_args DIR sets ROOT_ARGS to --root and a --root-update for each later
# root, in order and without gaps. With roots/1.json the chain starts there,
# as on a client that shipped with root 1; that is what lets a release carry
# the published entries forward after the targets or timestamp key was
# replaced. Without it, it starts at update-root.json.
root_args() {
    local dir="$1" v n f m first
    [[ -f "$dir/update-root.json" ]] ||
        die "no root of trust at $dir/update-root.json (docs/KEY-CEREMONY.md, \"Shipping root 1\")"
    v="$(root_version "$dir/update-root.json")" || die "cannot read the version of $dir/update-root.json"
    if [[ -f "$dir/roots/1.json" ]]; then
        first="$dir/roots/1.json"
        n=2
    else
        first="$dir/update-root.json"
        n=$((v + 1))
    fi
    ROOT_ARGS=(--root "$first")
    local newest="$first"
    while [[ -f "$dir/roots/$n.json" ]]; do
        ROOT_ARGS+=(--root-update "$dir/roots/$n.json")
        newest="$dir/roots/$n.json"
        n=$((n + 1))
    done
    for f in "$dir"/roots/*.json; do
        [[ -e "$f" ]] || continue
        m="$(basename "$f" .json)"
        [[ "$m" =~ ^[0-9]+$ && "$m" -lt "$n" ]] ||
            die "$f: roots are numbered 1, 2, 3, ... without gaps, up to the newest"
    done
    (( n - 1 >= v )) || die "$dir/update-root.json is root $v, but $dir/roots stops at $((n - 1))"
    cmp -s "$newest" "$dir/update-root.json" ||
        die "$dir/update-root.json is not the newest root ($newest is)"
}

# Every root from 2 on into DIR/roots (root 1 ships with every client and
# is never published).
copy_roots() {
    local from="$1" to="$2" f
    for f in "$from"/roots/*.json; do
        [[ -e "$f" && "$(basename "$f")" != 1.json ]] || continue
        mkdir -p "$to/roots"
        cp "$f" "$to/roots/"
    done
}

# PUBLISHED_ARGS: --published-timestamp/--published-targets for the
# documents in DIR, or nothing for the first release.
published_args() {
    local dir="$1"
    PUBLISHED_ARGS=()
    if [[ -f "$dir/timestamp.json" && -f "$dir/targets.json" ]]; then
        PUBLISHED_ARGS=(--published-timestamp "$dir/timestamp.json"
            --published-targets "$dir/targets.json")
    elif [[ -f "$dir/timestamp.json" || -f "$dir/targets.json" ]]; then
        die "$dir has only one of timestamp.json and targets.json"
    else
        echo "(nothing published yet: this is the first release)"
    fi
}

# Sign a timestamp for the targets envelope $1 with key $2 into $3. The
# version is the Unix time in seconds, so it goes up with every signing
# without needing the previous one; `verify` with the published documents
# catches a clock that went backwards.
sign_timestamp() {
    "$FARO_RELEASE" sign-timestamp --targets "$1" --version "$(now_s)" \
        --expires-ms "$(expires_ms "${FARO_TIMESTAMP_EXPIRY_HOURS:-24}")" \
        --key "$2" --out "$3"
}
