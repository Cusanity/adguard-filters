"""
AdGuard Filter Sync Daemon

Runs as a scheduled task/cron/launchd job to:
1. Read user rules from the local AdGuard installation
2. Fetch the current shared filter from GitHub
3. Merge (union) both rule sets
4. Push the merged result to GitHub if anything changed

Supported platforms:
  - Windows  : AdGuard for Windows (FLM SQLite at C:\\ProgramData\\Adguard\\FLM\\)
  - macOS    : AdGuard for Mac     (FLM SQLite in ~/Library/Group Containers/ or
                                    ~/Library/Application Support/AdGuard/)
  - Linux    : AdGuard Home        (YAML config or REST API at localhost:3000)

Override the DB/config path in config.json:
  "adguard_flm_db":   "/custom/path/to/agflm_standard.db"
  "adguard_home_url": "http://localhost:3000"   (Linux/AdGuard Home)
"""

import base64
import json
import os
import platform
import sqlite3
import sys
import shutil
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
ENV_PATH = SCRIPT_DIR / ".env"
LOG_PATH = SCRIPT_DIR / "sync.log"

NTFY_URL = "https://ntfy.cusanity.synology.me/alerts"


def notify_error(message):
    """Send an error alert to ntfy."""
    try:
        req = urllib.request.Request(
            NTFY_URL,
            data=message.encode("utf-8"),
            headers={
                "Title": "AdGuard Sync Error",
                "Priority": "high",
                "Tags": "warning",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log(f"WARNING: Failed to send ntfy alert: {e}")

ADGUARD_USER_FILTER_ID = -2147483648  # INT_MIN = user rules partition in FLM

# Known FLM database paths per platform (tried in order)
_FLM_PATHS = {
    "Windows": [
        Path(r"C:\ProgramData\Adguard\FLM\agflm_standard.db"),
    ],
    "Darwin": [
        # Mac App Store build (sandboxed, group container)
        Path.home() / "Library/Group Containers/TC3Q7MAJXF.com.adguard.mac/Library/Application Support/FLM/agflm_standard.db",
        # Direct-download build
        Path.home() / "Library/Application Support/AdGuard/FLM/agflm_standard.db",
        Path.home() / "Library/Application Support/com.adguard.mac.adguard/FLM/agflm_standard.db",
    ],
    # Linux/other: AdGuard Home (no desktop FLM app); handled separately via YAML/API
}

# AdGuard Home config search paths (Linux / self-hosted macOS)
_ADGUARD_HOME_YAML_PATHS = [
    Path.home() / "AdGuardHome/AdGuardHome.yaml",
    Path("/opt/AdGuardHome/AdGuardHome.yaml"),
    Path("/etc/adguardhome/AdGuardHome.yaml"),
    Path("/var/lib/adguardhome/AdGuardHome.yaml"),
]


def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_config():
    if not CONFIG_PATH.exists():
        msg = "config.json not found"
        log(f"ERROR: {msg}")
        notify_error(msg)
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_token():
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    if ENV_PATH.exists():
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("GITHUB_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    log("ERROR: GITHUB_TOKEN not found")
    notify_error("GITHUB_TOKEN not found in environment or .env file")
    sys.exit(1)


def github_api(method, url, token, data=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode()), resp.status
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        return {"error": error_body, "status": e.code}, e.code


# --- AdGuard rule reading (cross-platform) ---

def find_flm_db(config):
    """
    Locate the FLM SQLite database.
    Checks config override first, then platform-specific default paths.
    """
    # Config override
    override = config.get("adguard_flm_db")
    if override:
        p = Path(override)
        if p.exists():
            return p
        log(f"WARNING: adguard_flm_db in config.json not found: {override}")

    system = platform.system()
    candidates = _FLM_PATHS.get(system, [])
    for p in candidates:
        if p.exists():
            return p
    return None


def read_flm_db(db_path):
    """Read user rules from an AdGuard FLM SQLite database (Windows/macOS)."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        shutil.copy2(str(db_path), tmp_path)
    except Exception as e:
        log(f"ERROR copying FLM database: {e}")
        notify_error(f"Failed to copy FLM database: {e}")
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return set()

    rules = set()
    try:
        conn = sqlite3.connect(tmp_path, timeout=5)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT rules_text FROM rules_list WHERE filter_id = ?",
            (ADGUARD_USER_FILTER_ID,)
        )
        row = cursor.fetchone()
        if row and row[0]:
            for line in row[0].splitlines():
                line = line.strip()
                if line and not line.startswith("!") and not line.startswith("#"):
                    rules.add(line)
        conn.close()
    except Exception as e:
        log(f"ERROR reading FLM database: {e}")
        notify_error(f"Failed to read FLM database: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return rules


def read_adguard_home_rules(config):
    """
    Read user rules from AdGuard Home (Linux / self-hosted).
    Tries the REST API first, then falls back to YAML config file.
    """
    # --- REST API ---
    base_url = config.get("adguard_home_url", "http://localhost:3000").rstrip("/")
    ag_user = config.get("adguard_home_user", "")
    ag_pass = config.get("adguard_home_password", "")

    try:
        req = urllib.request.Request(f"{base_url}/control/filtering/get_rules")
        if ag_user:
            creds = base64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            raw = data.get("user_rules") or data.get("rules") or []
            rules = set()
            if isinstance(raw, list):
                for line in raw:
                    line = line.strip()
                    if line and not line.startswith("!") and not line.startswith("#"):
                        rules.add(line)
            elif isinstance(raw, str):
                for line in raw.splitlines():
                    line = line.strip()
                    if line and not line.startswith("!") and not line.startswith("#"):
                        rules.add(line)
            if rules:
                log(f"Read {len(rules)} rule(s) from AdGuard Home API ({base_url})")
                return rules
    except Exception as e:
        log(f"AdGuard Home API unavailable ({base_url}): {e}")

    # --- YAML fallback ---
    override_yaml = config.get("adguard_home_yaml")
    yaml_candidates = ([Path(override_yaml)] if override_yaml else []) + _ADGUARD_HOME_YAML_PATHS

    for yaml_path in yaml_candidates:
        if not yaml_path.exists():
            continue
        try:
            rules = set()
            in_user_rules = False
            with open(yaml_path, encoding="utf-8") as f:
                for line in f:
                    stripped = line.rstrip("\n")
                    if stripped.strip() == "user_rules:":
                        in_user_rules = True
                        continue
                    if in_user_rules:
                        # YAML list items start with "  - "
                        if stripped.startswith("  - "):
                            rule = stripped[4:].strip().strip("'\"")
                            if rule and not rule.startswith("!") and not rule.startswith("#"):
                                rules.add(rule)
                        elif stripped and not stripped.startswith(" "):
                            break  # next top-level key
            if rules:
                log(f"Read {len(rules)} rule(s) from AdGuard Home YAML ({yaml_path})")
                return rules
        except Exception as e:
            log(f"Error reading AdGuard Home YAML {yaml_path}: {e}")
            continue

    return set()


def read_adguard_rules(config):
    """
    Main entry point: read user rules from the local AdGuard installation.
    Dispatches to the right reader based on platform and config.
    """
    system = platform.system()
    log(f"Platform: {system}")

    # Linux (and explicitly configured AdGuard Home)
    if system == "Linux" or config.get("adguard_home_url") or config.get("adguard_home_yaml"):
        rules = read_adguard_home_rules(config)
        if rules:
            return rules
        # If on Linux with no AdGuard Home found, fall through to FLM check below
        if system == "Linux":
            log("No AdGuard Home found. Set 'adguard_home_url' or 'adguard_home_yaml' in config.json.")
            return set()

    # Windows / macOS: FLM SQLite database
    db_path = find_flm_db(config)
    if db_path:
        log(f"Found FLM database: {db_path}")
        return read_flm_db(db_path)

    log("ERROR: AdGuard FLM database not found.")
    if system == "Darwin":
        log("  Tried: " + ", ".join(str(p) for p in _FLM_PATHS.get("Darwin", [])))
        log("  Override with 'adguard_flm_db' in config.json if your path differs.")
    return set()


def get_github_filter(config, token):
    """Fetch the current filter file from GitHub."""
    owner = config["owner"]
    repo = config["repo"]
    path = config["filter_path"]
    branch = config.get("branch", "main")

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    result, status = github_api("GET", url, token)
    if status != 200:
        msg = f"Failed to fetch filter from GitHub (HTTP {status}): {result}"
        log(f"ERROR fetching filter from GitHub: {result}")
        notify_error(msg)
        return None, None
    content = base64.b64decode(result["content"]).decode("utf-8")
    return content, result["sha"]


def parse_filter(content):
    """Split filter into header and rules."""
    lines = content.split("\n")
    header_lines = []
    rule_lines = []
    header_done = False

    for line in lines:
        if not header_done and (line.startswith("!") or line.strip() == ""):
            header_lines.append(line)
        else:
            header_done = True
            rule_lines.append(line)

    return header_lines, rule_lines


def write_local_filter(config, content):
    """Write content to the local filter.txt file."""
    local_path = SCRIPT_DIR / config.get("filter_path", "filter.txt")
    try:
        local_path.write_text(content, encoding="utf-8")
    except Exception as e:
        log(f"WARNING: Could not update local {local_path.name}: {e}")


def merge_and_push(config, token, local_rules):
    """
    Merge local AdGuard rules with GitHub filter and push if changed.
    Always updates the local filter.txt to match GitHub (before and after push).
    Uses retry logic for concurrent edit handling.
    """
    max_retries = 3

    for attempt in range(max_retries):
        content, sha = get_github_filter(config, token)
        if content is None:
            return False

        # Keep local file up to date with whatever is on GitHub right now
        write_local_filter(config, content)

        header_lines, existing_rule_lines = parse_filter(content)
        existing_rules = set(r.strip() for r in existing_rule_lines if r.strip())

        # Find new rules not yet in GitHub
        new_rules = local_rules - existing_rules

        if not new_rules:
            log("No new rules to sync.")
            return True

        # Merge: existing + new, sorted
        all_rules = sorted(existing_rules | new_rules, key=str.lower)

        # Update timestamp
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        updated_header = []
        for line in header_lines:
            if line.startswith("! Last modified:"):
                updated_header.append(f"! Last modified: {now}")
            else:
                updated_header.append(line)

        new_content = "\n".join(updated_header + all_rules) + "\n"

        # Push
        owner = config["owner"]
        repo = config["repo"]
        path = config["filter_path"]
        branch = config.get("branch", "main")
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

        data = {
            "message": f"Auto-sync {len(new_rules)} rule(s) from {os.environ.get('COMPUTERNAME', platform.node())}",
            "content": base64.b64encode(new_content.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": branch,
        }

        result, status = github_api("PUT", url, token, data)
        if status in (200, 201):
            log(f"Synced {len(new_rules)} new rule(s) to GitHub.")
            write_local_filter(config, new_content)
            return True
        elif status == 409 and attempt < max_retries - 1:
            log("Conflict detected, retrying...")
            time.sleep(2)
            continue
        else:
            msg = f"Failed to push to GitHub (HTTP {status}): {result}"
            log(f"ERROR pushing to GitHub: {result}")
            notify_error(msg)
            return False

    msg = "Max retries exceeded while pushing to GitHub"
    log(f"ERROR: {msg}")
    notify_error(msg)
    return False


def main():
    log("=" * 50)
    log("AdGuard Filter Sync starting...")

    config = load_config()
    token = get_token()

    # Read rules from the local AdGuard installation
    local_rules = read_adguard_rules(config)

    if not local_rules:
        log("No user rules found in local AdGuard.")
        log("This is normal if you haven't added custom rules yet.")
        return

    log(f"Found {len(local_rules)} rule(s) in local AdGuard.")

    # Merge with GitHub and push
    merge_and_push(config, token, local_rules)
    log("Sync complete.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        log(f"FATAL: Unhandled exception: {e}")
        notify_error(f"Unhandled exception in sync_daemon: {e}")
        sys.exit(1)
