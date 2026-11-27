#!/bin/bash
# End-to-end test of the release scripts with throwaway keys, fake
# artifacts and a local git repository standing in for the publishing
# location. Needs no secret and touches nothing outside a temporary
# directory. CI runs it (the `release-scripts` job).
#
#   cargo build --release --locked -p faro-update --example faro-release
#   release/test-release.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
here="$repo/release"
# shellcheck source=release/lib.sh
. "$here/lib.sh"

t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
export FARO_UPDATES_GIT_URL="$t/updates.git"
git init -q --bare "$FARO_UPDATES_GIT_URL"
unset GITHUB_OUTPUT

step() { echo; echo "### $*"; }
fails() { # the command must fail
    if "$@" > "$t/out.txt" 2>&1; then
        cat "$t/out.txt"
        die "expected this to fail: $*"
    fi
}
published() { # a file at the publishing location
    git --git-dir="$FARO_UPDATES_GIT_URL" cat-file blob "main:$1"
}
targets_payload() {
    published targets.json | jq -r .payload | b64url_decode
}
listed() { # a target name, in the published targets.json
    targets_payload | jq -e --arg n "$1" '.targets[$n]' > /dev/null || die "$1 is not listed"
}
# The timestamp version is the time in seconds; sign at most once a second.
tick() { sleep 1; }

"$here/throwaway-keys.sh" "$t/keys"
keys=(--targets-key "$t/keys/targets.key.json" --timestamp-key "$t/keys/timestamp.key.json")
mkdir -p "$t/dist"
printf 'pkg one' > "$t/dist/Faro-0.1.0-beta.1.pkg"
printf 'msi one' > "$t/dist/Faro-0.1.0-beta.1-x64.msi"
printf 'server one' > "$t/dist/faro-server-0.1.0-beta.1-linux-aarch64"
b3hex() { "$FARO_RELEASE" describe-target --file "$1" | jq -r .blake3 | sed 's/^b3://'; }
# A model and a domain list: only the fields the scripts read.
mkdir -p "$t/dist/model" "$t/dist/blocklist"
printf 'weights one' > "$t/dist/model/test.onnx"
jq -n --arg b "$(b3hex "$t/dist/model/test.onnx")" \
    '{name: "test", version: "1.0.0+int8", file: "test.onnx", blake3: $b}' > "$t/dist/model/manifest.json"
printf 'list one' > "$t/dist/blocklist/domains.bin"
jq -n --arg b "$(b3hex "$t/dist/blocklist/domains.bin")" \
    '{version: "1.0.0", bundle: {file: "domains.bin", blake3: $b}, unapproved_included: false}' \
    > "$t/dist/blocklist/domains.manifest.json"
data=(--data "model=$t/dist/model/manifest.json"
      --data "blocklist:0.1.0=$t/dist/blocklist/domains.manifest.json")

step "first release: nothing published yet"
"$here/publish-layout.sh" pull "$t/pub1"
[[ -z "$(ls -A "$t/pub1")" ]] || die "pull of an empty repository wrote files"
"$here/build-layout.sh" --version 0.1.0-beta.1 \
    --artifact "client:macos:any:13=$t/dist/Faro-0.1.0-beta.1.pkg" \
    --artifact "client:windows:x86_64:10.0.19045=$t/dist/Faro-0.1.0-beta.1-x64.msi" \
    --artifact "server:linux:aarch64=$t/dist/faro-server-0.1.0-beta.1-linux-aarch64" \
    "${data[@]}" \
    --roots "$t/keys" --published "$t/pub1" "${keys[@]}" --out "$t/layout1"
[[ ! -e "$t/layout1/roots" ]] || die "root 1 must not be published"
"$here/publish-layout.sh" push "$t/layout1" "Faro 0.1.0-beta.1"
listed client/macos/Faro-0.1.0-beta.1.pkg
listed client/windows/Faro-0.1.0-beta.1-x64.msi
listed server/linux/faro-server-0.1.0-beta.1-linux-aarch64
targets_payload |
    jq -e '.targets["client/windows/Faro-0.1.0-beta.1-x64.msi"].custom
            | .kind == "client" and .platform == "windows" and .arch == "x86_64"
              and .version == "0.1.0-beta.1" and .min_os == "10.0.19045"' \
        > /dev/null || die "wrong Windows client entry"
[[ "$(published targets/client/windows/Faro-0.1.0-beta.1-x64.msi)" == "msi one" ]] || die "the MSI is not published"
listed model/any/test-1.0.0_int8-beta.data
listed blocklist/any/domains-1.0.0-beta.data
targets_payload |
    jq -e '.targets["model/any/test-1.0.0_int8-beta.data"].custom
            | .kind == "model" and .platform == "any" and .arch == "any"
              and .version == "1.0.0+int8" and .channels == ["beta"] and (has("min_client") | not)' \
        > /dev/null || die "wrong model entry"
targets_payload |
    jq -e '.targets["blocklist/any/domains-1.0.0-beta.data"].custom
            | .kind == "blocklist" and .version == "1.0.0" and .min_client == "0.1.0"' \
        > /dev/null || die "wrong blocklist entry"
[[ "$(published targets/model/any/test-1.0.0_int8-beta.data | head -c 8)" == FARODATA ]] ||
    die "the model is not a data bundle"
[[ "$(published targets/client/macos/Faro-0.1.0-beta.1.pkg)" == "pkg one" ]] || die "artifact not published"
[[ "$(published CNAME)" == updates.faro-project.org ]] || die "no CNAME"

step "a client package of the wrong kind, arch or version is refused"
printf 'msi' > "$t/dist/Faro-0.0.9-x64.msi"
for bad in "client:windows:x86_64:10.0.19045=$t/dist/Faro-0.0.9-x64.msi" \
           "client:windows:aarch64=$t/dist/Faro-0.1.0-beta.1-x64.msi" \
           "client:windows:x86_64=$t/dist/Faro-0.1.0-beta.1.pkg" \
           "client:macos:any:13=$t/dist/Faro-0.1.0-beta.1-x64.msi"; do
    fails "$here/build-layout.sh" --version 0.1.0-beta.1 --artifact "$bad" \
        --roots "$t/keys" --published "$t/pub1" "${keys[@]}" --out "$t/bad-layout"
    rm -rf "$t/bad-layout"
done

step "publishing the same layout again changes nothing"
"$here/publish-layout.sh" push "$t/layout1" "again" > "$t/out.txt"
grep -q "nothing to publish" "$t/out.txt" || die "a second push changed something"

step "re-signing the timestamp (no targets key)"
tick
"$here/publish-layout.sh" pull "$t/pub2"
"$here/resign-timestamp.sh" --roots "$t/keys" --published "$t/pub2" \
    --timestamp-key "$t/keys/timestamp.key.json" --out "$t/ts2"
[[ -f "$t/ts2/timestamp.json" && ! -e "$t/ts2/targets.json" ]] || die "expected a timestamp only"
"$here/publish-layout.sh" push "$t/ts2" "Re-sign the timestamp"
cmp -s <(published timestamp.json) "$t/ts2/timestamp.json" || die "timestamp not published"

step "renewing targets.json only when it is about to expire"
tick
"$here/publish-layout.sh" pull "$t/pub3"
"$here/resign-timestamp.sh" --roots "$t/keys" --published "$t/pub3" \
    --renew-targets "$t/keys/targets.key.json" --timestamp-key "$t/keys/timestamp.key.json" \
    --out "$t/ts3-early"
[[ -z "$(ls -A "$t/ts3-early")" ]] || die "renewed targets.json with 41 days left"
FARO_TARGETS_RENEW_DAYS=60 "$here/resign-timestamp.sh" --roots "$t/keys" --published "$t/pub3" \
    --renew-targets "$t/keys/targets.key.json" --timestamp-key "$t/keys/timestamp.key.json" \
    --out "$t/ts3"
[[ -f "$t/ts3/targets.json" && -f "$t/ts3/timestamp.json" ]] || die "targets.json was not renewed"
"$here/publish-layout.sh" push "$t/ts3" "Renew targets.json"
[[ "$(targets_payload | jq .version)" == 2 ]] || die "renewed targets.json is not version 2"
listed client/macos/Faro-0.1.0-beta.1.pkg

step "a renewed root: kept as roots/1.json and roots/2.json, update-root.json is root 2"
mkdir -p "$t/keys/roots"
cp "$t/keys/update-root.json" "$t/keys/roots/1.json"
jq -r .payload "$t/keys/update-root.json" | b64url_decode |
    jq --argjson e "$(expires_ms $((60 * 24)))" '.version = 2 | .expires_ms = $e' > "$t/root2.json"
"$FARO_RELEASE" sign-root --metadata "$t/root2.json" --key "$t/keys/root.key.json" \
    --out "$t/keys/roots/2.json" > /dev/null
# Not yet copied to update-root.json: refused.
if (root_args "$t/keys") > /dev/null 2>&1; then die "a stale update-root.json was accepted"; fi
cp "$t/keys/roots/2.json" "$t/keys/update-root.json"

step "second release: the first stays listed"
tick
printf 'pkg two' > "$t/dist/Faro-0.1.0.pkg"
"$here/publish-layout.sh" pull "$t/pub4"
"$here/build-layout.sh" --version 0.1.0 \
    --artifact "client:macos:any:13=$t/dist/Faro-0.1.0.pkg" "${data[@]}" \
    --roots "$t/keys" --published "$t/pub4" "${keys[@]}" --out "$t/layout4"
"$here/publish-layout.sh" push "$t/layout4" "Faro 0.1.0"
listed client/macos/Faro-0.1.0-beta.1.pkg
listed client/macos/Faro-0.1.0.pkg
# The same model, now for stable too: a second entry, the same bytes.
listed model/any/test-1.0.0_int8-beta.data
listed model/any/test-1.0.0_int8-stable.data
cmp -s <(published targets/model/any/test-1.0.0_int8-beta.data) \
    <(published targets/model/any/test-1.0.0_int8-stable.data) || die "the bundle is not reproducible"
cmp -s <(published roots/2.json) "$t/keys/roots/2.json" || die "root 2 not published"
targets_payload |
    jq -e '.targets["client/macos/Faro-0.1.0.pkg"].custom.channels == ["stable", "beta"]
        and .targets["client/macos/Faro-0.1.0-beta.1.pkg"].custom.channels == ["beta"]
        and .targets["client/macos/Faro-0.1.0.pkg"].custom.min_os == "13"
        and .version == 3' > /dev/null ||
    die "wrong channels, min_os or version"

step "without roots/1.json the chain starts at update-root.json"
mkdir -p "$t/ship2/roots"
cp "$t/keys/roots/2.json" "$t/ship2/update-root.json"
cp "$t/keys/roots/2.json" "$t/ship2/roots/2.json"
root_args "$t/ship2"
[[ "${ROOT_ARGS[*]}" == "--root $t/ship2/update-root.json" ]] || die "root 2 applied on top of itself"
"$FARO_RELEASE" verify "${ROOT_ARGS[@]}" --timestamp "$t/layout4/timestamp.json" \
    --targets "$t/layout4/targets.json" > /dev/null
mv "$t/ship2/roots/2.json" "$t/ship2/roots/4.json"
if (root_args "$t/ship2") > /dev/null 2>&1; then die "a gap in roots/ was accepted"; fi

step "replacing the targets and timestamp keys carries the entries forward"
tick
for role in targets timestamp; do
    "$FARO_RELEASE" keygen --out "$t/keys/$role-2.key.json" > "$t/$role-2.pub"
done
jq -r .payload "$t/keys/update-root.json" | b64url_decode |
    jq --arg ti "$(cut -d' ' -f1 "$t/targets-2.pub")" --arg tp "$(cut -d' ' -f2 "$t/targets-2.pub")" \
       --arg si "$(cut -d' ' -f1 "$t/timestamp-2.pub")" --arg sp "$(cut -d' ' -f2 "$t/timestamp-2.pub")" \
       '(.roles.targets.keyids[0]) as $ot | (.roles.timestamp.keyids[0]) as $os
        | .version = 3 | del(.keys[$ot], .keys[$os]) | .keys[$ti] = $tp | .keys[$si] = $sp
        | .roles.targets.keyids = [$ti] | .roles.timestamp.keyids = [$si]' > "$t/root3.json"
"$FARO_RELEASE" sign-root --metadata "$t/root3.json" --key "$t/keys/root.key.json" \
    --out "$t/keys/roots/3.json" > /dev/null
cp "$t/keys/roots/3.json" "$t/keys/update-root.json"
"$here/publish-layout.sh" pull "$t/pub-rot"
# The timestamp alone can't be re-signed: targets.json carries the old key.
fails "$here/resign-timestamp.sh" --roots "$t/keys" --published "$t/pub-rot" \
    --timestamp-key "$t/keys/timestamp-2.key.json" --out "$t/rot-ts"
grep -q -- "--renew-targets" "$t/out.txt" || { cat "$t/out.txt"; die "no hint"; }
# Renewing works even with plenty of days left (forced here; the workflow
# forces it when the targets key changed).
FARO_TARGETS_RENEW_DAYS=1000 "$here/resign-timestamp.sh" --roots "$t/keys" --published "$t/pub-rot" \
    --renew-targets "$t/keys/targets-2.key.json" --timestamp-key "$t/keys/timestamp-2.key.json" \
    --out "$t/rot" > /dev/null
[[ -f "$t/rot/targets.json" ]] || die "targets.json not renewed with the new key"
printf 'pkg three' > "$t/dist/Faro-0.1.1.pkg"
"$here/build-layout.sh" --version 0.1.1 \
    --artifact "client:macos:any:13=$t/dist/Faro-0.1.1.pkg" \
    --roots "$t/keys" --published "$t/pub-rot" \
    --targets-key "$t/keys/targets-2.key.json" --timestamp-key "$t/keys/timestamp-2.key.json" \
    --out "$t/layout-rot"
"$here/publish-layout.sh" push "$t/layout-rot" "Faro 0.1.1, new online keys"
listed client/macos/Faro-0.1.0-beta.1.pkg
listed client/macos/Faro-0.1.1.pkg
cmp -s <(published roots/3.json) "$t/keys/roots/3.json" || die "root 3 not published"
if git --git-dir="$FARO_UPDATES_GIT_URL" cat-file -e main:roots/1.json 2>/dev/null; then
    die "root 1 was published"
fi
keys=(--targets-key "$t/keys/targets-2.key.json" --timestamp-key "$t/keys/timestamp-2.key.json")

step "a published artifact name never gets new bytes"
tick
printf 'pkg two, changed' > "$t/dist/Faro-0.1.0.pkg"
"$here/publish-layout.sh" pull "$t/pub5"
fails "$here/build-layout.sh" --version 0.1.0 \
    --artifact "client:macos:any:13=$t/dist/Faro-0.1.0.pkg" \
    --roots "$t/keys" --published "$t/pub5" "${keys[@]}" --out "$t/layout5"
grep -q "never reused" "$t/out.txt" || { cat "$t/out.txt"; die "wrong error"; }
mkdir -p "$t/evil/targets/client/macos"
cp "$t/layout4/timestamp.json" "$t/evil/"
printf 'other bytes' > "$t/evil/targets/client/macos/Faro-0.1.0.pkg"
fails "$here/publish-layout.sh" push "$t/evil" "replace an artifact"
grep -q "never replaced" "$t/out.txt" || { cat "$t/out.txt"; die "wrong error"; }

step "models and blocklists are checked before anything is signed"
printf 'weights changed' > "$t/dist/model/test.onnx"
fails "$here/build-layout.sh" --version 0.1.2 --data "model=$t/dist/model/manifest.json" \
    --roots "$t/keys" --published "$t/pub5" "${keys[@]}" --out "$t/layout-m1"
grep -q "pins" "$t/out.txt" || { cat "$t/out.txt"; die "wrong error"; }
# The manifest updated, but the version kept: refused, the name is taken.
jq --arg b "$(b3hex "$t/dist/model/test.onnx")" '.blake3 = $b' "$t/dist/model/manifest.json" \
    > "$t/m.json" && mv "$t/m.json" "$t/dist/model/manifest.json"
fails "$here/build-layout.sh" --version 0.1.0 --data "model=$t/dist/model/manifest.json" \
    --roots "$t/keys" --published "$t/pub5" "${keys[@]}" --out "$t/layout-m2"
grep -q "never reused" "$t/out.txt" || { cat "$t/out.txt"; die "wrong error"; }
jq '.unapproved_included = true' "$t/dist/blocklist/domains.manifest.json" > "$t/unapproved.json"
cp "$t/dist/blocklist/domains.bin" "$t/domains.bin"
fails "$here/build-layout.sh" --version 0.1.2 --data "blocklist=$t/unapproved.json" \
    --roots "$t/keys" --published "$t/pub5" "${keys[@]}" --out "$t/layout-m3"
grep -q "unapproved" "$t/out.txt" || { cat "$t/out.txt"; die "wrong error"; }
fails "$here/build-layout.sh" --version 0.1.2 --data "font=$t/dist/model/manifest.json" \
    --roots "$t/keys" --published "$t/pub5" "${keys[@]}" --out "$t/layout-m4"

step "metadata from other keys is refused"
"$here/throwaway-keys.sh" "$t/other"
fails "$here/build-layout.sh" --version 0.2.0 \
    --artifact "client:macos:any:13=$t/dist/Faro-0.1.0-beta.1.pkg" \
    --roots "$t/other" --published "$t/pub5" \
    --targets-key "$t/other/targets.key.json" --timestamp-key "$t/other/timestamp.key.json" \
    --out "$t/layout6"

step "a timestamp version that goes backwards is refused"
mkdir -p "$t/ts7"
"$FARO_RELEASE" sign-timestamp --targets "$t/pub5/targets.json" --version 1 \
    --expires-ms "$(expires_ms 24)" --key "$t/keys/timestamp-2.key.json" \
    --out "$t/ts7/timestamp.json" > /dev/null
root_args "$t/keys"
published_args "$t/pub5"
fails "$FARO_RELEASE" verify "${ROOT_ARGS[@]}" "${PUBLISHED_ARGS[@]}" \
    --timestamp "$t/ts7/timestamp.json" --targets "$t/pub5/targets.json"

echo
echo "release scripts: all checks passed"
