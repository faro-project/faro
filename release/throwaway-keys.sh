#!/bin/bash
# Throwaway update keys and a root 1 signed with them, for dry runs and
# tests only (never for a release; the real keys come from the key
# ceremony, docs/KEY-CEREMONY.md).
#
#   release/throwaway-keys.sh DIR
#
# Writes DIR/root.key.json, DIR/targets.key.json, DIR/timestamp.key.json
# and DIR/update-root.json (root 1), laid out like release/. Metadata signed
# with these keys verifies only against that root, which nothing trusts.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=release/lib.sh
. "$repo/release/lib.sh"

dir="${1:?usage: $0 DIR}"
mkdir -p "$dir"
for role in root targets timestamp; do
    "$FARO_RELEASE" keygen --out "$dir/$role.key.json" > "$dir/$role.pub"
done
id() { cut -d' ' -f1 "$dir/$1.pub"; }
pub() { cut -d' ' -f2 "$dir/$1.pub"; }
cat > "$dir/root.unsigned.json" <<EOF
{
  "version": 1,
  "expires_ms": $(expires_ms $((30 * 24))),
  "keys": {
    "$(id root)": "$(pub root)",
    "$(id targets)": "$(pub targets)",
    "$(id timestamp)": "$(pub timestamp)"
  },
  "roles": {
    "root": {"keyids": ["$(id root)"], "threshold": 1},
    "targets": {"keyids": ["$(id targets)"], "threshold": 1},
    "timestamp": {"keyids": ["$(id timestamp)"], "threshold": 1}
  }
}
EOF
"$FARO_RELEASE" sign-root --metadata "$dir/root.unsigned.json" \
    --key "$dir/root.key.json" --out "$dir/update-root.json" > /dev/null
rm -f "$dir"/*.pub "$dir/root.unsigned.json"
echo "throwaway keys and root in $dir"
