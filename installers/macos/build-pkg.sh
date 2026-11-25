#!/bin/bash
# Build the macOS installer package (ARCHITECTURE.md §3.3, §3.8).
#
#   installers/macos/build-pkg.sh --dev            # unsigned development package
#   installers/macos/build-pkg.sh --dev --arch arm64   # one architecture only
#   FARO_SIGN_IDENTITY="Developer ID Application: …" \
#   FARO_INSTALLER_IDENTITY="Developer ID Installer: …" \
#   FARO_TEAM_ID=ABCDE12345 \
#   [FARO_NOTARY_PROFILE=faro-notary] \
#   FARO_UPDATE_ROOT=path/to/1.root.json \
#   installers/macos/build-pkg.sh                  # release package
#
# Output: target/pkg/Faro-<version>[-dev].pkg
#
# The programs are universal (arm64 + x86_64) binaries: cargo builds each
# architecture and `lipo` joins them. `--arch arm64` or `--arch x86_64`
# builds for one architecture only, which is faster for local testing.
# A universal build needs both Rust targets
# (`rustup target add aarch64-apple-darwin x86_64-apple-darwin`).
# MACOSX_DEPLOYMENT_TARGET is set from the minimum macOS version in
# Distribution.xml.in, so every slice runs on that version.
#
# What it installs (faro_platform_macos::pkg_layout):
#   /Library/Faro/bin/faro-service              the privileged service
#   /Library/Faro/bin/faro-uninstall            removes Faro, telling allies first
#   /Library/Faro/Faro Agent.app                the session agent (org.faro.agent)
#   /Library/Faro/service.toml.default          copied to the state dir if absent
#   /Library/Faro/update-root.json              the project's update root of trust
#                                               (FARO_UPDATE_ROOT; optional for --dev)
#   /Library/LaunchDaemons/org.faro.service.plist
#   /Library/LaunchAgents/org.faro.agent.plist  global: every account's session
#
# A release package needs a Developer ID: the service refuses agents whose
# code signature does not satisfy `ipc.agent_requirement`, which the
# package's default config derives from FARO_TEAM_ID. `--dev` builds
# faro-service with the `dev` feature instead (agents accepted by uid alone)
# and ad-hoc signs everything. Never ship a `--dev` package.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
dev=0
arch=universal
while (( $# )); do
    case "$1" in
        --dev) dev=1 ;;
        --arch) arch="${2:-}"; shift ;;
        --arch=*) arch="${1#--arch=}" ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
case "$arch" in
    universal) triples=(aarch64-apple-darwin x86_64-apple-darwin) ;;
    arm64) triples=(aarch64-apple-darwin) ;;
    x86_64) triples=(x86_64-apple-darwin) ;;
    *) echo "--arch must be universal, arm64 or x86_64" >&2; exit 2 ;;
esac

if [[ "$(uname -s)" != Darwin ]]; then
    echo "build-pkg.sh runs on macOS only" >&2
    exit 1
fi

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -n1)"
[[ -n "$version" ]] || { echo "cannot read the workspace version" >&2; exit 1; }

if (( dev )); then
    name="Faro-$version-dev"
    features=(--features faro-service/dev)
    : "${FARO_SIGN_IDENTITY:=-}"
else
    name="Faro-$version"
    features=()
    # Without the root of trust the service never updates itself, so a
    # release package must ship it.
    for v in FARO_SIGN_IDENTITY FARO_INSTALLER_IDENTITY FARO_TEAM_ID FARO_UPDATE_ROOT; do
        if [[ -z "${!v:-}" ]]; then
            echo "a release package needs $v (or build an unsigned one with --dev)" >&2
            exit 1
        fi
    done
    if [[ ! "$FARO_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
        echo "FARO_TEAM_ID must be a 10-character Apple team ID" >&2
        exit 1
    fi
fi

# Every slice is built for the oldest macOS the package installs on.
min_os="$(sed -n 's/.*<os-version min="\([0-9.]*\)".*/\1/p' "$here/Distribution.xml.in")"
[[ -n "$min_os" ]] || { echo "cannot read the minimum macOS version from Distribution.xml.in" >&2; exit 1; }
export MACOSX_DEPLOYMENT_TARGET="$min_os"

sysroot="$(rustc --print sysroot)"
for t in "${triples[@]}"; do
    if [[ ! -d "$sysroot/lib/rustlib/$t/lib" ]]; then
        echo "the Rust target $t is not installed: run \`rustup target add $t\`," >&2
        echo "or build for one architecture with --arch" >&2
        exit 1
    fi
done

out="$repo/target/pkg"
work="$out/work"
root="$work/root"
rm -rf "$work"
mkdir -p "$root" "$out"

echo "==> building faro-service and faro-agent ($version; ${triples[*]}; macOS $min_os+)"
cargo build --manifest-path "$repo/Cargo.toml" --release --locked \
    -p faro-service -p faro-agent "${features[@]+"${features[@]}"}" \
    "${triples[@]/#/--target=}"
# One binary per program, with a slice for each architecture.
bin="$work/bin"
mkdir -p "$bin"
for b in faro-service faro-agent; do
    slices=()
    for t in "${triples[@]}"; do
        slices+=("$repo/target/$t/release/$b")
    done
    lipo -create -output "$bin/$b" "${slices[@]}"
done

echo "==> staging the payload"
# Launchd plists, checked in and kept equal to the generator by
# crates/faro-platform-macos/tests/installer_plists.rs.
cp -R "$here/payload/." "$root/"
install -d -m 755 "$root/Library/Faro/bin"
install -m 755 "$bin/faro-service" "$root/Library/Faro/bin/faro-service"
install -m 755 "$here/faro-uninstall" "$root/Library/Faro/bin/faro-uninstall"
if [[ -n "${FARO_UPDATE_ROOT:-}" ]]; then
    [[ -f "$FARO_UPDATE_ROOT" ]] || { echo "FARO_UPDATE_ROOT: no such file $FARO_UPDATE_ROOT" >&2; exit 1; }
    install -m 644 "$FARO_UPDATE_ROOT" "$root/Library/Faro/update-root.json"
fi

app="$root/Library/Faro/Faro Agent.app"
install -d -m 755 "$app/Contents/MacOS"
install -m 755 "$bin/faro-agent" "$app/Contents/MacOS/faro-agent"
sed "s/@VERSION@/$version/g" "$here/Info.plist.in" > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"

# The default service config. Only the agent requirement differs from the
# built-in defaults; postinstall copies it into place if there is none yet.
{
    echo "# Faro service configuration (installed by the package)."
    echo "# See crates/faro-service/src/config.rs for every setting."
    if (( dev )); then
        echo "# Development package: no agent_requirement; the dev build accepts"
        echo "# agents by uid alone."
    else
        echo
        echo "[ipc]"
        echo "agent_requirement = 'anchor apple generic and identifier \"org.faro.agent\" and certificate leaf[subject.OU] = \"$FARO_TEAM_ID\"'"
    fi
} > "$root/Library/Faro/service.toml.default"
chmod 644 "$root/Library/Faro/service.toml.default"

# Extended attributes (quarantine, provenance) would end up in the payload
# as AppleDouble `._*` files.
xattr -cr "$root"

echo "==> signing (${FARO_SIGN_IDENTITY})"
sign=(codesign --force --sign "$FARO_SIGN_IDENTITY")
if (( ! dev )); then
    sign+=(--options runtime --timestamp)
fi
"${sign[@]}" --identifier org.faro.service "$root/Library/Faro/bin/faro-service"
"${sign[@]}" "$app"
codesign --verify --strict --verbose=1 "$app"
codesign --verify --strict --verbose=1 "$root/Library/Faro/bin/faro-service"
if (( ! dev )); then
    req="anchor apple generic and identifier \"org.faro.agent\" and certificate leaf[subject.OU] = \"$FARO_TEAM_ID\""
    codesign --verify --test-requirement="=$req" "$app"
fi

echo "==> building the package"
# Installed locations must not move: launchd plists point at them and the
# agent's code-signing identity is checked by path at connect time.
pkgbuild --analyze --root "$root" "$work/component.plist" >/dev/null
n="$(/usr/libexec/PlistBuddy -c 'Print' "$work/component.plist" | grep -c 'RootRelativeBundlePath' || true)"
for ((i = 0; i < n; i++)); do
    # (Recent pkgbuild omits the key, which means relocatable.)
    plutil -replace "$i.BundleIsRelocatable" -bool NO "$work/component.plist"
done
chmod 755 "$here/scripts/preinstall" "$here/scripts/postinstall"
COPYFILE_DISABLE=1 pkgbuild --root "$root" \
    --component-plist "$work/component.plist" \
    --scripts "$here/scripts" \
    --identifier org.faro.pkg \
    --version "$version" \
    --install-location / \
    --ownership recommended \
    "$work/faro-component.pkg" >/dev/null

# Claim only the architectures the binaries were built for, as a sorted
# list: arm64,x86_64 for a universal package.
slice_archs() { lipo -archs "$1" | tr ' ' '\n' | sort | paste -sd, -; }
archs="$(slice_archs "$bin/faro-agent")"
[[ "$archs" == "$(slice_archs "$bin/faro-service")" ]] || {
    echo "faro-service and faro-agent were built for different architectures" >&2
    exit 1
}
sed -e "s/@VERSION@/$version/g" -e "s/@ARCHS@/$archs/g" \
    "$here/Distribution.xml.in" > "$work/Distribution.xml"
resources="$work/resources"
cp -R "$here/resources" "$resources"
if (( dev )); then
    # Say so on the first page.
    sed -i '' 's|<!-- DEV-BANNER -->|<p class="dev"><strong>Development package.</strong> Unsigned, and its service accepts any program running as a logged-in user as the agent. Do not use it to monitor anyone.</p>|' \
        "$resources/welcome.html"
fi
product=(productbuild --distribution "$work/Distribution.xml" --resources "$resources" --package-path "$work")
if (( ! dev )); then
    product+=(--sign "$FARO_INSTALLER_IDENTITY" --timestamp)
fi
"${product[@]}" "$out/$name.pkg" >/dev/null

if (( ! dev )) && [[ -n "${FARO_NOTARY_PROFILE:-}" ]]; then
    echo "==> notarizing"
    xcrun notarytool submit "$out/$name.pkg" --keychain-profile "$FARO_NOTARY_PROFILE" --wait
    xcrun stapler staple "$out/$name.pkg"
fi

echo "==> $out/$name.pkg"
