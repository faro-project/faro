# Shared by preinstall and postinstall (sourced; runs as root).

DAEMON_LABEL=org.faro.service
AGENT_LABEL=org.faro.agent
DAEMON_PLIST=/Library/LaunchDaemons/org.faro.service.plist
AGENT_PLIST=/Library/LaunchAgents/org.faro.agent.plist

log() { echo "faro: $*"; }

# The uids of every account with a GUI login session, including accounts
# switched away from with fast user switching: each such session runs its
# own loginwindow as that user, whatever its uid (Guest is 201). Skipped: uid
# 0, the login window itself, and Setup Assistant's _mbsetupuser. Not a
# `uid >= 501` test, which dropped Guest and low-uid admin accounts.
gui_uids() {
    ps -axo uid=,comm= | awk -v skip="$(id -u _mbsetupuser 2>/dev/null || echo 0)" '$2 ~ /\/loginwindow$/ && $1 != 0 && $1 != skip { print $1 }' | sort -un
}
