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
    echo "Pulling latest scripts..."
    git -C "$SCRIPT_DIR" checkout -- filter.txt 2>/dev/null
    git -C "$SCRIPT_DIR" pull
    python3 "$SCRIPT_DIR/sync_daemon.py"
    exit $?
fi

# --- Find Python 3 ---
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 not found. Install it with: brew install python" >&2
    exit 1
fi

resolve_log_dir() {
    "$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1])

try:
    config = json.loads((script_dir / "config.json").read_text())
except Exception:
    print(script_dir)
    raise SystemExit

log_path = (config.get("log_path") or "").strip()
log_dir  = (config.get("log_dir")  or "").strip()

if log_path:
    print(Path(log_path).expanduser().parent)
elif log_dir:
    print(Path(log_dir).expanduser())
else:
    print(script_dir)
PY
}

LOG_DIR="$(resolve_log_dir)"
LOG_PATH="$LOG_DIR/sync.log"
mkdir -p "$LOG_DIR"

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

# --- Write wrapper that pulls latest scripts and sets env ---
WRAPPER="$SCRIPT_DIR/sync_runner.sh"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
LOG="${LOG_PATH}"
mkdir -p "${LOG_DIR}"
# Truncate if last written on a previous day
if [ -f "\$LOG" ] && [ "\$(date -r "\$LOG" +%F)" != "\$(date +%F)" ]; then : > "\$LOG"; fi
exec >> "\$LOG" 2>&1
git -C "${SCRIPT_DIR}" checkout -- filter.txt
git -C "${SCRIPT_DIR}" pull
export GITHUB_TOKEN="${TOKEN}"
exec "${PYTHON}" "${SCRIPT_DIR}/sync_daemon.py"
EOF
chmod 700 "$WRAPPER"  # contains token

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
        <string>/bin/bash</string>
        <string>${WRAPPER}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>StartInterval</key>
    <integer>${INTERVAL_SEC}</integer>
    <key>RunAtLoad</key>
    <true/>
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
