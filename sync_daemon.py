"""
AdGuard Filter Sync Daemon

Runs as a Windows Scheduled Task with elevated privileges (SYSTEM) to:
1. Read user rules from AdGuard's locked SQLite database
2. Fetch the current shared filter from GitHub
3. Merge (union) both rule sets
4. Push the merged result to GitHub if anything changed

This enables automatic bi-directional sync:
- Rules added in AdGuard UI → this daemon extracts them → pushes to GitHub → other devices pull
- Rules added via push.py on any device → GitHub → AdGuard pulls the subscription URL
"""

import base64
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
ENV_PATH = SCRIPT_DIR / ".env"
LOG_PATH = SCRIPT_DIR / "sync.log"

# AdGuard for Windows stores its DB here
ADGUARD_DB_PATHS = [
    Path(r"C:\ProgramData\Adguard\adguard.db"),
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
        log("ERROR: config.json not found")
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


def find_adguard_db():
    """Find the AdGuard database file."""
    for path in ADGUARD_DB_PATHS:
        if path.exists():
            return path
    log("ERROR: AdGuard database not found")
    return None


def read_adguard_user_rules(db_path):
    """
    Read user rules from AdGuard's SQLite database.
    Must be run with sufficient privileges (SYSTEM or Administrator).
    """
    rules = set()

    try:
        # Connect in read-only mode to avoid conflicts with AdGuard service
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        # Get table names to find where rules are stored
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        # AdGuard stores user rules in various tables depending on version
        # Common table names: 'rules', 'user_rules', 'filter_rules'
        rule_tables = [t for t in tables if 'rule' in t.lower()]
        filter_tables = [t for t in tables if 'filter' in t.lower()]

        # Try known patterns for AdGuard for Windows DB schema
        for table in rule_tables + filter_tables:
            try:
                cursor.execute(f"SELECT * FROM [{table}] LIMIT 1")
                columns = [desc[0] for desc in cursor.description]

                # Look for columns that might contain rule text
                text_cols = [c for c in columns if any(
                    kw in c.lower() for kw in ['rule', 'text', 'content', 'line', 'value']
                )]

                if not text_cols:
                    # Just try all text columns
                    text_cols = columns

                for col in text_cols:
                    try:
                        cursor.execute(f"SELECT [{col}] FROM [{table}]")
                        for row in cursor.fetchall():
                            val = row[0]
                            if isinstance(val, str) and val.strip():
                                # Filter: only keep things that look like filter rules
                                line = val.strip()
                                if is_filter_rule(line):
                                    rules.add(line)
                    except Exception:
                        continue
            except Exception:
                continue

        # Also check if there's a dedicated user rules storage
        # AdGuard sometimes stores them as a blob or newline-separated text
        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info([{table}])")
                cols_info = cursor.fetchall()
                blob_cols = [(info[1], info[2]) for info in cols_info
                             if info[2].upper() in ('BLOB', 'TEXT', 'CLOB')]

                for col_name, col_type in blob_cols:
                    cursor.execute(f"SELECT [{col_name}] FROM [{table}]")
                    for row in cursor.fetchall():
                        val = row[0]
                        if isinstance(val, bytes):
                            try:
                                val = val.decode('utf-8')
                            except Exception:
                                continue
                        if isinstance(val, str) and '\n' in val and len(val) > 20:
                            # Might be a multi-line rules blob
                            for line in val.split('\n'):
                                line = line.strip()
                                if is_filter_rule(line):
                                    rules.add(line)
            except Exception:
                continue

        conn.close()
    except sqlite3.OperationalError as e:
        log(f"ERROR: Cannot open AdGuard DB: {e}")
        log("Make sure this script runs with Administrator/SYSTEM privileges.")
        return set()
    except Exception as e:
        log(f"ERROR reading AdGuard DB: {e}")
        return set()

    return rules


def is_filter_rule(line):
    """Check if a line looks like a valid AdGuard/uBlock filter rule."""
    if not line:
        return False
    # Skip comments and metadata
    if line.startswith('!') or line.startswith('#'):
        return False
    # Skip very short lines (likely not rules)
    if len(line) < 3:
        return False

    # Positive signals: looks like a filter rule
    indicators = [
        line.startswith('||'),       # Domain block
        line.startswith('@@'),       # Exception
        line.startswith('|'),        # URL start anchor
        line.startswith('*'),        # Wildcard
        '##' in line,                # Cosmetic
        '#@#' in line,               # Cosmetic exception
        '#$#' in line,               # CSS injection
        '#%#' in line,               # JS injection
        line.startswith('0.0.0.0'),  # Hosts format
        line.startswith('127.0.0.1'),# Hosts format
        '^$' in line,                # Rule with options
        line.endswith('^'),          # Domain block ending
    ]
    return any(indicators)


def get_github_filter(config, token):
    """Fetch the current filter file from GitHub."""
    owner = config["owner"]
    repo = config["repo"]
    path = config["filter_path"]
    branch = config.get("branch", "main")

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    result, status = github_api("GET", url, token)
    if status != 200:
        log(f"ERROR fetching filter from GitHub: {result}")
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


def merge_and_push(config, token, local_rules):
    """
    Merge local AdGuard rules with GitHub filter and push if changed.
    Uses retry logic for concurrent edit handling.
    """
    max_retries = 3

    for attempt in range(max_retries):
        content, sha = get_github_filter(config, token)
        if content is None:
            return False

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
            "message": f"Auto-sync {len(new_rules)} rule(s) from {os.environ.get('COMPUTERNAME', 'device')}",
            "content": base64.b64encode(new_content.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": branch,
        }

        result, status = github_api("PUT", url, token, data)
        if status in (200, 201):
            log(f"Synced {len(new_rules)} new rule(s) to GitHub.")
            return True
        elif status == 409 and attempt < max_retries - 1:
            log("Conflict detected, retrying...")
            time.sleep(2)
            continue
        else:
            log(f"ERROR pushing to GitHub: {result}")
            return False

    log("ERROR: Max retries exceeded.")
    return False


def main():
    log("=" * 50)
    log("AdGuard Filter Sync starting...")

    config = load_config()
    token = get_token()

    # Step 1: Find and read AdGuard database
    db_path = find_adguard_db()
    if not db_path:
        sys.exit(1)

    log(f"Reading AdGuard DB: {db_path}")
    local_rules = read_adguard_user_rules(db_path)

    if not local_rules:
        log("No user rules found in AdGuard DB (or DB schema unrecognized).")
        log("If this is a fresh install, rules will accumulate as you add them.")
        return

    log(f"Found {len(local_rules)} rule(s) in local AdGuard DB.")

    # Step 2: Merge with GitHub and push
    merge_and_push(config, token, local_rules)
    log("Sync complete.")


if __name__ == "__main__":
    main()
