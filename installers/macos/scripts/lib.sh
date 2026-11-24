# Shared by preinstall and postinstall (sourced; runs as root).

DAEMON_LABEL=org.faro.service
AGENT_LABEL=org.faro.agent
DAEMON_PLIST=/Library/LaunchDaemons/org.faro.service.plist
AGENT_PLIST=/Library/LaunchAgents/org.faro.agent.plist

log() { echo "faro: $*"; }

# The uids of every account with a GUI login session, including accounts
# switched away from with fast user switching: each such session runs its
# own loginwindow as that user. (At the login window, loginwindow runs as
# root, which the uid filter drops.)
gui_uids() {
    ps -axo uid=,comm= | awk '$2 ~ /\/loginwindow$/ && $1 >= 501 { print $1 }' | sort -un
}
