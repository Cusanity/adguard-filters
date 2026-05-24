#!/usr/bin/env bash
# Install/uninstall the AdGuard Filter Sync launchd job on macOS.
#
# Usage:
#   ./install_launchd.sh              # install (runs every 30 min)
#   ./install_launchd.sh --interval 15
#   ./install_launchd.sh --uninstall
#   ./install_launchd.sh --run-now

set -euo pipefail

LABEL="com.adguard.filter-sync"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERVAL_SEC=1800  # 30 minutes

UNINSTALL=false
RUN_NOW=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall) UNINSTALL=true; shift ;;
        --run-now)   RUN_NOW=true;   shift ;;
        --interval)  INTERVAL_SEC=$(( $2 * 60 )); shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if $UNINSTALL; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "Removed launchd job: $LABEL"
    exit 0
fi

if $RUN_NOW; then
    echo "Running sync now..."
    python3 "$SCRIPT_DIR/sync_daemon.py"
    exit $?
fi

# --- Find Python 3 ---
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 not found. Install it with: brew install python" >&2
    exit 1
fi

# --- Load token ---
TOKEN=""
ENV_FILE="$SCRIPT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
    TOKEN=$(grep '^GITHUB_TOKEN=' "$ENV_FILE" | cut -d= -f2- | tr -d "\"'" | head -1)
fi
if [[ -z "$TOKEN" ]]; then
    echo "ERROR: GITHUB_TOKEN not found in .env" >&2
    exit 1
fi

# --- Write plist ---
mkdir -p "$(dirname "$PLIST")"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON}</string>
        <string>${SCRIPT_DIR}/sync_daemon.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GITHUB_TOKEN</key>
        <string>${TOKEN}</string>
    </dict>
    <key>StartInterval</key>
    <integer>${INTERVAL_SEC}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${SCRIPT_DIR}/sync.log</string>
    <key>StandardErrorPath</key>
    <string>${SCRIPT_DIR}/sync.log</string>
</dict>
</plist>
EOF

chmod 600 "$PLIST"  # contains token

# Reload
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo ""
echo "Installed launchd job: $LABEL"
echo "  Interval : every $(( INTERVAL_SEC / 60 )) minutes"
echo "  Python   : $PYTHON"
echo "  Script   : $SCRIPT_DIR/sync_daemon.py"
echo "  Plist    : $PLIST"
echo ""
echo "To test immediately : ./install_launchd.sh --run-now"
echo "To remove           : ./install_launchd.sh --uninstall"
