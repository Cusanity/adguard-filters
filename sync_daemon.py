"""
AdGuard Filter Sync Daemon

Runs as a Windows Scheduled Task with elevated privileges (SYSTEM) to:
1. Read user rules from AdGuard's database (ESE format)
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
import re
import subprocess
import sys
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

ADGUARD_DB = Path(r"C:\ProgramData\Adguard\adguard.db")


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


# --- AdGuard DB Reading (ESE / SQLite / raw) ---

def identify_db_format(db_path):
    """Identify the database format by reading magic bytes."""
    try:
        with open(db_path, 'rb') as f:
            header = f.read(64)
    except PermissionError:
        return "locked"
    except Exception as e:
        return f"error:{e}"

    if header[:16] == b'SQLite format 3\x00':
        return "sqlite"

    # ESE/JET database check - multiple known signatures
    # JET Blue (ESE) has checksum at offset 4, and database signature
    # The file typically has 0xEFCDAB89 somewhere in the first page
    if len(header) >= 8:
        # ESE databases have a specific page size and format
        # Check for common ESE patterns
        val_at_4 = int.from_bytes(header[4:8], 'little')
        if val_at_4 == 0xEFCDAB89:
            return "ese"
        # Another ESE indicator: magic at different offset depending on version
        if b'\xef\xcd\xab\x89' in header:
            return "ese"

    # Try broader ESE detection - check if esentutl can parse it
    return "unknown"


def copy_db_via_vss(db_path, dest_path):
    """Copy a locked database file using Volume Shadow Copy."""
    try:
        result = subprocess.run(
            ["esentutl", "/y", str(db_path), "/vss", "/d", str(dest_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True
        log(f"VSS copy failed: {result.stderr.strip()}")

        # Fallback: try direct copy (works if running as SYSTEM)
        import shutil
        shutil.copy2(str(db_path), str(dest_path))
        return True
    except Exception as e:
        log(f"Failed to copy DB: {e}")
        return False


def read_ese_database(db_path):
    """
    Read rules from an ESE (Extensible Storage Engine) database.
    Uses esentutl to dump table info, then reads the raw file for text patterns.
    """
    rules = set()

    # Strategy 1: Use raw binary scan for filter rules in the DB file
    # ESE stores data in pages, but text strings are often readable in raw bytes
    rules.update(scan_file_for_rules(db_path))

    return rules


def scan_file_for_rules(file_path):
    """
    Scan a binary file for text that looks like AdGuard filter rules.
    Works regardless of the database format by finding UTF-8/UTF-16 strings.
    """
    rules = set()

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        log(f"Cannot read file: {e}")
        return rules

    # Scan for UTF-8 strings that look like filter rules
    # Pattern: lines starting with || or @@ or containing ## (common filter patterns)
    utf8_rules = extract_rules_from_bytes(data, 'utf-8')
    rules.update(utf8_rules)

    # Also try UTF-16LE (Windows native string encoding)
    utf16_rules = extract_rules_from_bytes(data, 'utf-16-le')
    rules.update(utf16_rules)

    return rules


def extract_rules_from_bytes(data, encoding):
    """Extract filter rules from raw bytes using a specific encoding."""
    rules = set()

    try:
        if encoding == 'utf-8':
            text = data.decode('utf-8', errors='ignore')
        else:
            text = data.decode(encoding, errors='ignore')
    except Exception:
        return rules

    # Find sequences that look like filter rules
    # Domain blocking rules: ||domain.tld^
    for match in re.finditer(r'\|\|[a-zA-Z0-9][\w.\-]+\^(?:\$[^\x00\n\r]{0,100})?', text):
        rule = match.group(0).strip()
        if is_filter_rule(rule) and is_plausible_user_rule(rule):
            rules.add(rule)

    # Exception rules: @@||domain.tld^
    for match in re.finditer(r'@@\|\|[a-zA-Z0-9][\w.\-]+\^(?:\$[^\x00\n\r]{0,100})?', text):
        rule = match.group(0).strip()
        if is_filter_rule(rule):
            rules.add(rule)

    # Cosmetic rules: domain.tld##selector
    for match in re.finditer(r'[a-zA-Z0-9][\w.\-]*##[^\x00\n\r]{1,200}', text):
        rule = match.group(0).strip()
        if is_filter_rule(rule) and not looks_like_garbage(rule):
            rules.add(rule)

    # Host-format rules: 0.0.0.0 domain or 127.0.0.1 domain
    for match in re.finditer(r'(?:0\.0\.0\.0|127\.0\.0\.1)\s+[a-zA-Z0-9][\w.\-]+', text):
        rule = match.group(0).strip()
        if is_filter_rule(rule):
            rules.add(rule)

    # Newline-separated blocks that look like filter lists
    # (AdGuard might store user rules as a single text blob)
    for match in re.finditer(r'(?:(?:\|\|[\w.\-]+\^[^\x00\n\r]*[\n\r]){2,})', text):
        block = match.group(0)
        for line in block.split('\n'):
            line = line.strip().strip('\r')
            if is_filter_rule(line):
                rules.add(line)

    return rules


def is_filter_rule(line):
    """Check if a line looks like a valid AdGuard filter rule."""
    if not line:
        return False
    if line.startswith('!') or line.startswith('#'):
        return False
    if len(line) < 4 or len(line) > 500:
        return False

    indicators = [
        line.startswith('||'),
        line.startswith('@@'),
        line.startswith('|'),
        '##' in line,
        '#@#' in line,
        '#$#' in line,
        '#%#' in line,
        line.startswith('0.0.0.0 '),
        line.startswith('127.0.0.1 '),
    ]
    return any(indicators)


def is_plausible_user_rule(rule):
    """
    Filter out rules that are obviously from built-in filter lists rather than user-added.
    User rules tend to be for specific, recognizable domains.
    """
    # Skip if it contains null bytes or control characters (binary artifact)
    if any(ord(c) < 32 and c not in '\n\r\t' for c in rule):
        return False
    # Skip if domain part looks like random garbage (malware domains in built-in lists)
    domain = extract_domain_from_rule(rule)
    if domain:
        # Very long random-looking domains are likely from subscription lists, not user rules
        if len(domain) > 50 and not any(c == '-' for c in domain):
            return False
        # Domains with excessive randomness (no vowels in a long segment)
        parts = domain.split('.')
        for part in parts:
            if len(part) > 15 and not re.search(r'[aeiou]', part):
                return False
    return True


def extract_domain_from_rule(rule):
    """Extract domain from a rule like ||domain.com^"""
    m = re.match(r'^(?:@@)?\|\|([a-zA-Z0-9][\w.\-]+)\^', rule)
    return m.group(1) if m else None


def looks_like_garbage(text):
    """Detect binary/garbage strings that aren't real rules."""
    if '\x00' in text:
        return True
    # Too many non-printable or unusual characters
    weird_chars = sum(1 for c in text if ord(c) > 127 or ord(c) < 32)
    return weird_chars > len(text) * 0.1


def read_adguard_rules():
    """
    Main entry point: read user rules from AdGuard's database.
    Handles different database formats automatically.
    """
    if not ADGUARD_DB.exists():
        log("ERROR: AdGuard database not found at expected path.")
        return set()

    log(f"Checking database format...")
    fmt = identify_db_format(ADGUARD_DB)
    log(f"Database format: {fmt}")

    if fmt == "locked":
        # Try VSS copy
        log("DB file locked, attempting VSS copy...")
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            tmp_path = tmp.name
        try:
            if copy_db_via_vss(ADGUARD_DB, tmp_path):
                fmt = identify_db_format(Path(tmp_path))
                log(f"Copied DB format: {fmt}")
                rules = read_from_db_file(Path(tmp_path), fmt)
            else:
                rules = set()
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return rules

    return read_from_db_file(ADGUARD_DB, fmt)


def read_from_db_file(db_path, fmt):
    """Read rules from a database file of known format."""
    if fmt == "sqlite":
        return read_sqlite_database(db_path)
    elif fmt in ("ese", "unknown"):
        # For ESE or unknown formats, scan raw bytes
        return read_ese_database(db_path)
    else:
        log(f"Cannot handle format: {fmt}")
        return set()


def read_sqlite_database(db_path):
    """Read rules from a SQLite database."""
    import sqlite3
    rules = set()
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info([{table}])")
                cols = cursor.fetchall()
                text_cols = [c[1] for c in cols if c[2].upper() in ('TEXT', 'BLOB', 'CLOB', '')]

                for col in text_cols:
                    cursor.execute(f"SELECT [{col}] FROM [{table}]")
                    for row in cursor.fetchall():
                        val = row[0]
                        if isinstance(val, bytes):
                            val = val.decode('utf-8', errors='ignore')
                        if isinstance(val, str):
                            for line in val.split('\n'):
                                line = line.strip()
                                if is_filter_rule(line):
                                    rules.add(line)
            except Exception:
                continue
        conn.close()
    except Exception as e:
        log(f"SQLite error: {e}")
        # Fallback to raw scan
        rules = scan_file_for_rules(db_path)
    return rules


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

    # Read rules from AdGuard's database
    log(f"Reading AdGuard DB: {ADGUARD_DB}")
    local_rules = read_adguard_rules()

    if not local_rules:
        log("No user rules found in AdGuard DB.")
        log("This is normal if you haven't added custom rules yet.")
        return

    log(f"Found {len(local_rules)} rule(s) in local AdGuard.")

    # Merge with GitHub and push
    merge_and_push(config, token, local_rules)
    log("Sync complete.")


if __name__ == "__main__":
    main()
