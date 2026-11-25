#!/bin/bash
# Check faro-uninstall's decisions without touching the system: a copy runs
# against a fake /Library in a temporary directory, with launchctl, pkgutil,
# ps and id replaced by stubs that log their arguments, and a fake
# faro-service whose `goodbye` exits with a chosen status.
#
#   installers/macos/test-uninstall.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "test-uninstall: FAIL: $*" >&2; exit 1; }

stubs="$work/stubs"
mkdir -p "$stubs"
for cmd in launchctl pkgutil; do
    printf '#!/bin/bash\necho "%s $*" >> "$CALLS"\n' "$cmd" > "$stubs/$cmd"
done
printf '#!/bin/bash\necho 0\n' > "$stubs/id"
printf '#!/bin/bash\necho "  501 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"\necho "    0 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"\n' > "$stubs/ps"
chmod 755 "$stubs"/*

# Lay out a fake installation under $1 and print the path of the copied
# uninstaller, its constants pointing there.
install_fake() {
    local root="$1"
    mkdir -p "$root/Library/LaunchDaemons" "$root/Library/LaunchAgents" \
        "$root/Library/Faro/bin" "$root/Library/Application Support/Faro"
    touch "$root/Library/LaunchDaemons/org.faro.service.plist" \
        "$root/Library/LaunchAgents/org.faro.agent.plist" \
        "$root/Library/Application Support/Faro/device.key"
    cat > "$root/Library/Faro/bin/faro-service" <<'EOF'
#!/bin/bash
echo "faro-service $*" >> "$CALLS"
[[ "$1" == goodbye ]] && exit "$GOODBYE_RC"
exit 0
EOF
    chmod 755 "$root/Library/Faro/bin/faro-service"
    sed -e "s|^DAEMON_PLIST=/|DAEMON_PLIST=$root/|" \
        -e "s|^AGENT_PLIST=/|AGENT_PLIST=$root/|" \
        -e "s|^FARO_DIR=/|FARO_DIR=$root/|" \
        -e "s|^STATE_DIR=\"/|STATE_DIR=\"$root/|" \
        "$here/faro-uninstall" > "$root/Library/Faro/bin/faro-uninstall"
    chmod 755 "$root/Library/Faro/bin/faro-uninstall"
    grep -q "^FARO_DIR=$root/" "$root/Library/Faro/bin/faro-uninstall" || fail "could not redirect the paths"
    echo "$root/Library/Faro/bin/faro-uninstall"
}

# run NAME GOODBYE_RC STDIN ARGS...: sets $root, $status, $calls.
run() {
    local name="$1" rc="$2" input="$3"
    shift 3
    root="$work/$name"
    local script
    script="$(install_fake "$root")"
    export CALLS="$work/$name.calls" GOODBYE_RC="$rc"
    : > "$CALLS"
    set +e
    PATH="$stubs:$PATH" "$script" "$@" <<< "$input" > "$work/$name.out" 2>&1
    status=$?
    set -e
    calls="$(cat "$CALLS")"
}

removed() {
    [[ ! -e "$root/Library/Faro" ]] || fail "$1: /Library/Faro is still there"
    [[ ! -e "$root/Library/Application Support/Faro" ]] || fail "$1: the state directory is still there"
    [[ ! -e "$root/Library/LaunchDaemons/org.faro.service.plist" ]] || fail "$1: the daemon plist is still there"
    [[ ! -e "$root/Library/LaunchAgents/org.faro.agent.plist" ]] || fail "$1: the agent plist is still there"
    grep -q "^launchctl bootout gui/501/org.faro.agent" <<< "$calls" || fail "$1: the agent was not stopped"
    if grep -q "gui/0/" <<< "$calls"; then fail "$1: touched the login window's session"; fi
    grep -q "^pkgutil --forget org.faro.pkg" <<< "$calls" || fail "$1: the receipt was not forgotten"
}
kept() {
    [[ -e "$root/Library/Faro/bin/faro-service" ]] || fail "$1: the programs were removed"
    [[ -e "$root/Library/Application Support/Faro/device.key" ]] || fail "$1: the state was removed"
    [[ -e "$root/Library/LaunchDaemons/org.faro.service.plist" ]] || fail "$1: the daemon plist was removed"
}
not_restarted() {
    if grep -q "^launchctl bootstrap" <<< "$calls"; then fail "$1: the service was started again"; fi
}
# The service stops before the goodbye, which comes before any removal.
ordered() {
    local stop goodbye
    stop="$(grep -n "^launchctl bootout system/org.faro.service" <<< "$calls" | cut -d: -f1)"
    goodbye="$(grep -n "^faro-service goodbye --reason uninstalled" <<< "$calls" | cut -d: -f1)"
    [[ -n "$stop" && -n "$goodbye" && "$stop" -lt "$goodbye" ]] || fail "$1: stop then goodbye, got: $calls"
}

run delivered 0 "" --yes
(( status == 0 )) || fail "delivered: exit $status: $(cat "$work/delivered.out")"
ordered delivered; removed delivered; not_restarted delivered

run queued 3 "" --yes
(( status == 0 )) || fail "queued: exit $status"
ordered queued; removed queued; not_restarted queued
grep -q "missed check-in" "$work/queued.out" || fail "queued: does not say what allies will see"

run unreachable 1 "" --yes
(( status != 0 )) || fail "unreachable: exited 0"
ordered unreachable; kept unreachable
grep -q "^launchctl bootstrap system $root/Library/LaunchDaemons/org.faro.service.plist" <<< "$calls" \
    || fail "unreachable: the service was not started again: $calls"
if grep -q "bootout gui/" <<< "$calls"; then fail "unreachable: agents were stopped"; fi

run forced 1 "" --yes --force
(( status == 0 )) || fail "forced: exit $status"
ordered forced; removed forced; not_restarted forced

run declined 0 "n"
(( status != 0 )) || fail "declined: exited 0"
kept declined
if grep -q "bootout\|goodbye" <<< "$calls"; then fail "declined: acted anyway: $calls"; fi

run confirmed 0 "yes"
(( status == 0 )) || fail "confirmed: exit $status"
removed confirmed

echo "test-uninstall: all cases pass"
