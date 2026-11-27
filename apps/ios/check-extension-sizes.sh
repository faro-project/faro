#!/bin/bash
# Fails if one of the 6 MB extensions (FaroMonitor, FaroShield,
# FaroShieldAction; docs/IOS.md §6.3, §13) has grown past its size budget,
# or if the Rust core or FaroKitApp (the app and tunnel's half of the Swift
# package, docs/DEVELOPMENT.md) got linked into it. Run it on a built app:
#
#   apps/ios/check-extension-sizes.sh PATH/TO/Faro.app
#
# Measure a Release build: Debug binaries are larger and not representative.
# The budget (bytes, default 704 KiB) is a tripwire, not a memory estimate:
# the Rust core is megabytes, so linking it by mistake fails at once, and
# so does a dependency that quietly pulls in a big framework. Raise
# FARO_EXTENSION_BUDGET deliberately, with a reason in the commit.
set -euo pipefail

app="${1:?usage: check-extension-sizes.sh PATH/TO/Faro.app}"
budget="${FARO_EXTENSION_BUDGET:-720896}"
fail=0

for name in FaroMonitor FaroShield FaroShieldAction; do
    bin="$app/PlugIns/$name.appex/$name"
    if [[ ! -f "$bin" ]]; then
        echo "FAIL $name: $bin not found" >&2
        fail=1
        continue
    fi
    size="$(stat -f %z "$bin")"
    status=ok
    if (( size > budget )); then
        status="FAIL over the budget of $budget bytes"
        fail=1
    fi
    # The exported names of the Rust core and its UniFFI scaffolding.
    # (grep -c, not -q: with pipefail, -q's early exit would make strings
    # die of SIGPIPE and the test come out false on a big binary.)
    if (( $(strings -a "$bin" | grep -c -e uniffi_faro_mobile -e faro_mobile) > 0 )); then
        status="FAIL links the Rust core"
        fail=1
    fi
    # FaroKitApp's module name is in the Swift symbols and metadata of
    # whatever links it.
    if (( $(strings -a "$bin" | grep -c FaroKitApp) > 0 )); then
        status="FAIL links FaroKitApp"
        fail=1
    fi
    printf '%-18s %9d bytes  %s\n' "$name" "$size" "$status"
done
exit "$fail"
