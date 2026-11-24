#!/bin/bash
# Check a built package without installing it: the payload has every file
# at its fixed location with root ownership, the agent app carries the
# right bundle identifier, the install scripts are present, and the
# installer only installs for the whole computer.
#
#   installers/macos/check-pkg.sh target/pkg/Faro-<version>[-dev].pkg
set -euo pipefail

pkg="${1:?usage: check-pkg.sh PKG}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "check-pkg: $*" >&2; exit 1; }

pkgutil --expand "$pkg" "$work/x"
component="$work/x/faro-component.pkg"
[[ -d "$component" ]] || fail "no faro-component.pkg inside"

dist="$work/x/Distribution"
grep -q 'enable_localSystem="true"' "$dist" || fail "must install for the whole computer"
grep -q 'enable_currentUserHome="false"' "$dist" || fail "must not offer a per-user install"
grep -q 'hostArchitectures="[a-z0-9_,]*"' "$dist" || fail "hostArchitectures not filled in"

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
expect "Library/Faro/Faro Agent.app/Contents/MacOS/faro-agent" 100755
expect "Library/Faro/Faro Agent.app/Contents/Info.plist" 100644
expect "Library/Faro/service.toml.default" 100644
expect "Library/LaunchDaemons/org.faro.service.plist" 100644
expect "Library/LaunchAgents/org.faro.agent.plist" 100644

info="$work/payload/Library/Faro/Faro Agent.app/Contents/Info.plist"
[[ "$(plutil -extract CFBundleIdentifier raw "$info")" == org.faro.agent ]] || fail "agent bundle id"
[[ "$(plutil -extract LimitLoadToSessionType raw "$work/payload/Library/LaunchAgents/org.faro.agent.plist")" == Aqua ]] \
    || fail "the agent must load in every GUI session"
codesign --verify --strict "$work/payload/Library/Faro/Faro Agent.app" || fail "agent signature"
[[ "$(codesign -dv "$work/payload/Library/Faro/Faro Agent.app" 2>&1 | sed -n 's/^Identifier=//p')" == org.faro.agent ]] \
    || fail "agent signing identifier"

echo "check-pkg: $pkg is well-formed"
