#!/usr/bin/env bash
# Install/uninstall the AdGuard Filter Sync cron job on Linux.
# Works with AdGuard Home (REST API or YAML config).
#
# Usage:
#   ./install_cron.sh              # install (runs every 30 min)
#   ./install_cron.sh --interval 15
#   ./install_cron.sh --uninstall
#   ./install_cron.sh --run-now

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON_TAG="# adguard-filter-sync"
INTERVAL=30  # minutes

UNINSTALL=false
RUN_NOW=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall) UNINSTALL=true; shift ;;
        --run-now)   RUN_NOW=true;   shift ;;
        --interval)  INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if $UNINSTALL; then
    crontab -l 2>/dev/null | grep -v "$CRON_TAG" | crontab -
    echo "Removed cron job."
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
    echo "ERROR: Python 3 not found." >&2
    exit 1
fi

resolve_log_path() {
    "$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1])
default = script_dir / "sync.log"

try:
    config = json.loads((script_dir / "config.json").read_text())
except Exception:
    print(default)
    raise SystemExit

log_path = (config.get("log_path") or "").strip()
log_dir = (config.get("log_dir") or "").strip()

if log_path:
    print(Path(log_path).expanduser())
elif log_dir:
    print(Path(log_dir).expanduser() / "sync.log")
else:
    print(default)
PY
}

LOG_PATH="$(resolve_log_path)"
mkdir -p "$(dirname "$LOG_PATH")"

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
mkdir -p "$(dirname "${LOG_PATH}")"
export SYNC_LOG_PATH="${LOG_PATH}"
git -C "${SCRIPT_DIR}" checkout -- filter.txt >> "${LOG_PATH}" 2>&1
git -C "${SCRIPT_DIR}" pull >> "${LOG_PATH}" 2>&1
export GITHUB_TOKEN="${TOKEN}"
exec "${PYTHON}" "${SCRIPT_DIR}/sync_daemon.py"
EOF
chmod 700 "$WRAPPER"  # contains token

# --- Install cron entry ---
# Cron expression: every N minutes
if [[ "$INTERVAL" -eq 30 ]]; then
    CRON_EXPR="*/30 * * * *"
elif [[ "$INTERVAL" -eq 60 ]]; then
    CRON_EXPR="0 * * * *"
else
    CRON_EXPR="*/${INTERVAL} * * * *"
fi

# Remove old entry, add new one
( crontab -l 2>/dev/null | grep -v "$CRON_TAG" ; \
    echo "${CRON_EXPR} \"${WRAPPER}\" >> \"${LOG_PATH}\" 2>&1 ${CRON_TAG}" \
) | crontab -

echo ""
echo "Installed cron job."
echo "  Schedule : $CRON_EXPR (every $INTERVAL min)"
echo "  Python   : $PYTHON"
echo "  Wrapper  : $WRAPPER"
echo ""
echo "Make sure config.json has AdGuard Home settings:"
echo "  \"adguard_home_url\": \"http://localhost:3000\""
echo "  \"adguard_home_user\": \"admin\"  (if auth is enabled)"
echo "  \"adguard_home_password\": \"...\""
echo ""
echo "To test immediately : ./install_cron.sh --run-now"
echo "To remove           : ./install_cron.sh --uninstall"
