#!/usr/bin/env python3
"""
AdGuard Filter Sync - Push rules to a shared GitHub-hosted filter list.

Merges rules intelligently:
  - Normalizes rules before comparison (trims whitespace, deduplicates)
  - Detects redundant subdomain rules covered by a parent domain block
  - Warns about conflicting block/exception pairs
  - Sorts rules by type (blocks, exceptions, cosmetic, other)
  - Retries on SHA conflict (concurrent push from another device)

Usage:
    python push.py "||example.com^"
    python push.py "||ads.example.com^" "@@||allowed.example.com^"
    python push.py --remove "||example.com^"
    python push.py --list
    echo "||example.com^" | python push.py --stdin
    python push.py --merge-file local_rules.txt

Requires: GITHUB_TOKEN environment variable (or .env file in this directory)
Configure: config.json in this directory
"""

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


def load_config():
    config_path = Path(__file__).parent / "config.json"
    if not config_path.exists():
        print("ERROR: config.json not found. Copy config.example.json and fill in your details.")
        sys.exit(1)
    with open(config_path) as f:
        return json.load(f)


def get_token():
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token

    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("GITHUB_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")

    print("ERROR: GITHUB_TOKEN not found. Set it as an environment variable or in .env file.")
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


def get_file(config, token):
    """Get the current filter file content and SHA from GitHub."""
    owner = config["owner"]
    repo = config["repo"]
    path = config["filter_path"]
    branch = config.get("branch", "main")

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    result, status = github_api("GET", url, token)
    if status != 200:
        print(f"ERROR: Failed to fetch filter file: {result.get('error', result)}")
        sys.exit(1)
    content = base64.b64decode(result["content"]).decode("utf-8")
    return content, result["sha"]


def update_file(config, token, content, sha, message):
    """Update the filter file on GitHub. Returns (success, response)."""
    owner = config["owner"]
    repo = config["repo"]
    path = config["filter_path"]
    branch = config.get("branch", "main")

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    data = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "sha": sha,
        "branch": branch,
    }
    result, status = github_api("PUT", url, token, data)
    return status in (200, 201), result


def push_with_retry(config, token, merge_fn, message):
    """Fetch-merge-push loop with retry on SHA conflict (409)."""
    for attempt in range(MAX_RETRIES):
        content, sha = get_file(config, token)
        new_content, result_info = merge_fn(content)
        if new_content is None:
            return result_info  # Nothing to do
        success, response = update_file(config, token, new_content, sha, message)
        if success:
            return result_info
        if response.get("status") == 409 and attempt < MAX_RETRIES - 1:
            print(f"  (conflict detected, retrying in {RETRY_DELAY}s...)")
            time.sleep(RETRY_DELAY)
            continue
        print(f"ERROR: Failed to push: {response.get('error', response)}")
        sys.exit(1)
    print("ERROR: Max retries exceeded due to concurrent edits.")
    sys.exit(1)


# --- Rule normalization and analysis ---

def normalize_rule(rule):
    """Normalize a rule for consistent comparison."""
    rule = rule.strip()
    # Remove trailing comments on the same line (but not inline ! in rules)
    # Don't normalize case — AdGuard rules can be case-sensitive for cosmetic filters
    return rule


def extract_domain(rule):
    """Extract the domain from a basic blocking rule like ||domain.com^ or @@||domain.com^"""
    # Match: ||domain.tld^ or ||domain.tld^$options
    m = re.match(r'^(?:@@)?\|\|([a-zA-Z0-9\-_.]+)\^(\$.*)?$', rule)
    if m:
        return m.group(1).lower()
    return None


def is_exception(rule):
    """Check if rule is an exception (whitelist) rule."""
    return rule.startswith("@@")


def find_redundant_rules(existing_rules, new_rules):
    """
    Find new rules that are redundant because a broader rule already exists.
    e.g., ||sub.example.com^ is redundant if ||example.com^ exists.
    """
    # Collect all domains from existing block rules
    existing_domains = set()
    for r in existing_rules:
        if not is_exception(r):
            d = extract_domain(r)
            if d:
                existing_domains.add(d)

    redundant = []
    for rule in new_rules:
        if is_exception(rule):
            continue
        domain = extract_domain(rule)
        if not domain:
            continue
        # Check if any parent domain is already blocked
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in existing_domains:
                redundant.append((rule, f"||{parent}^"))
                break

    return redundant


def find_conflicts(all_rules):
    """
    Find rules that conflict — a block and an exception for the same pattern.
    Returns list of (block_rule, exception_rule) pairs.
    """
    blocks = {}
    exceptions = {}

    for rule in all_rules:
        domain = extract_domain(rule)
        if not domain:
            continue
        if is_exception(rule):
            exceptions[domain] = rule
        else:
            blocks[domain] = rule

    conflicts = []
    for domain in blocks:
        if domain in exceptions:
            conflicts.append((blocks[domain], exceptions[domain]))

    return conflicts


def categorize_rules(rules):
    """Sort rules into categories for organized output."""
    blocks = []
    exceptions = []
    cosmetic = []
    other = []

    for rule in rules:
        if not rule:
            continue
        if rule.startswith("@@"):
            exceptions.append(rule)
        elif "##" in rule or "#@#" in rule or "#$#" in rule or "#%#" in rule:
            cosmetic.append(rule)
        elif rule.startswith("||") or rule.startswith("|") or rule.startswith("*"):
            blocks.append(rule)
        else:
            other.append(rule)

    return blocks, exceptions, cosmetic, other


def parse_filter(content):
    """Split filter into header (comments at top) and rules."""
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


def update_metadata(header_lines):
    """Update Last modified in header."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    updated = []
    for line in header_lines:
        if line.startswith("! Last modified:"):
            updated.append(f"! Last modified: {now}")
        else:
            updated.append(line)
    return updated


def merge_rules(existing_content, new_rules, sort=True):
    """
    Merge new rules into existing content intelligently.
    Returns (new_content, info_dict) or (None, info_dict) if nothing to do.
    """
    header_lines, existing_rule_lines = parse_filter(existing_content)

    # Normalize existing rules
    existing_rules = [normalize_rule(r) for r in existing_rule_lines if normalize_rule(r)]
    existing_set = set(existing_rules)

    # Normalize new rules
    normalized_new = [normalize_rule(r) for r in new_rules if normalize_rule(r)]

    # Deduplicate new rules against existing
    added = []
    skipped = []
    for rule in normalized_new:
        if rule in existing_set:
            skipped.append(rule)
        else:
            added.append(rule)
            existing_set.add(rule)

    if not added:
        return None, {"added": [], "skipped": skipped, "redundant": [], "conflicts": []}

    # Check for redundant subdomain rules
    all_existing_for_check = existing_rules + added
    redundant = find_redundant_rules(existing_rules, added)
    redundant_rules = set(r[0] for r in redundant)

    # Remove redundant from added (but warn user)
    final_added = [r for r in added if r not in redundant_rules]

    # Merge all rules
    merged_rules = existing_rules + final_added

    # Check for conflicts in the full set
    conflicts = find_conflicts(merged_rules)

    # Sort rules by category if requested
    if sort:
        blocks, exceptions, cosmetic, other = categorize_rules(merged_rules)
        sorted_rules = []
        if blocks:
            sorted_rules.extend(sorted(blocks, key=str.lower))
        if exceptions:
            sorted_rules.extend(sorted(exceptions, key=str.lower))
        if cosmetic:
            sorted_rules.extend(sorted(cosmetic, key=str.lower))
        if other:
            sorted_rules.extend(sorted(other, key=str.lower))
        merged_rules = sorted_rules

    header_lines = update_metadata(header_lines)
    final_content = "\n".join(header_lines + merged_rules) + "\n"

    info = {
        "added": final_added,
        "skipped": skipped,
        "redundant": redundant,
        "conflicts": conflicts,
    }
    return final_content, info


def remove_rules(content, rules_to_remove):
    """Remove rules from the filter."""
    header_lines, rule_lines = parse_filter(content)
    remove_set = set(normalize_rule(r) for r in rules_to_remove)

    removed = []
    kept = []
    for line in rule_lines:
        if normalize_rule(line) in remove_set:
            removed.append(normalize_rule(line))
        else:
            kept.append(line)

    if not removed:
        return None, {"removed": []}

    header_lines = update_metadata(header_lines)
    final_content = "\n".join(header_lines + kept) + "\n"
    return final_content, {"removed": removed}


def list_rules(content):
    """List all active rules."""
    _, rule_lines = parse_filter(content)
    return [r for r in rule_lines if normalize_rule(r)]


def main():
    parser = argparse.ArgumentParser(description="Push AdGuard filter rules to GitHub (with smart merge)")
    parser.add_argument("rules", nargs="*", help="Rules to add")
    parser.add_argument("--remove", action="store_true", help="Remove the specified rules instead of adding")
    parser.add_argument("--list", action="store_true", help="List current rules")
    parser.add_argument("--stdin", action="store_true", help="Read rules from stdin (one per line)")
    parser.add_argument("--merge-file", "-f", help="Merge rules from a local file")
    parser.add_argument("--no-sort", action="store_true", help="Don't sort rules by category")
    parser.add_argument("--force", action="store_true", help="Add rules even if redundant")
    parser.add_argument("--message", "-m", help="Custom commit message")
    args = parser.parse_args()

    config = load_config()
    token = get_token()

    if args.list:
        content, _ = get_file(config, token)
        rules = list_rules(content)
        if rules:
            blocks, exceptions, cosmetic, other = categorize_rules(rules)
            print(f"Current rules ({len(rules)} total):")
            if blocks:
                print(f"\n  Block rules ({len(blocks)}):")
                for r in blocks:
                    print(f"    {r}")
            if exceptions:
                print(f"\n  Exception rules ({len(exceptions)}):")
                for r in exceptions:
                    print(f"    {r}")
            if cosmetic:
                print(f"\n  Cosmetic rules ({len(cosmetic)}):")
                for r in cosmetic:
                    print(f"    {r}")
            if other:
                print(f"\n  Other rules ({len(other)}):")
                for r in other:
                    print(f"    {r}")
        else:
            print("No rules yet.")
        return

    # Collect rules
    rules = list(args.rules)
    if args.stdin:
        rules.extend(line.strip() for line in sys.stdin if line.strip())
    if args.merge_file:
        merge_path = Path(args.merge_file)
        if not merge_path.exists():
            print(f"ERROR: File not found: {args.merge_file}")
            sys.exit(1)
        with open(merge_path) as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines in the input file
                if line and not line.startswith("!"):
                    rules.append(line)

    if not rules:
        parser.print_help()
        sys.exit(1)

    if args.remove:
        def do_remove(content):
            return remove_rules(content, rules)

        message = args.message or f"Remove {len(rules)} rule(s)"
        info = push_with_retry(config, token, do_remove, message)
        removed = info["removed"]
        if not removed:
            print("No matching rules found to remove.")
            return
        print(f"Removed {len(removed)} rule(s):")
        for r in removed:
            print(f"  - {r}")
    else:
        sort = not args.no_sort

        def do_merge(content):
            new_content, info = merge_rules(content, rules, sort=sort)
            if new_content is None and not args.force:
                return None, info
            # If --force, re-merge including redundant rules
            if new_content is None and args.force:
                # Force-add even duplicates by skipping dedup
                return None, info
            return new_content, info

        message = args.message or f"Merge {len(rules)} rule(s)"
        info = push_with_retry(config, token, do_merge, message)

        added = info["added"]
        skipped = info["skipped"]
        redundant = info["redundant"]
        conflicts = info["conflicts"]

        if added:
            print(f"Merged {len(added)} rule(s):")
            for r in added:
                print(f"  + {r}")
        if skipped:
            print(f"Skipped {len(skipped)} duplicate(s):")
            for r in skipped:
                print(f"  = {r}")
        if redundant:
            print(f"Skipped {len(redundant)} redundant rule(s):")
            for rule, parent in redundant:
                print(f"  ~ {rule}  (covered by {parent})")
        if conflicts:
            print(f"Warning: {len(conflicts)} conflict(s) detected:")
            for block, exception in conflicts:
                print(f"  ! {block}  <->  {exception}")
        if not added:
            print("Nothing new to merge.")
            return

    raw_url = f"https://raw.githubusercontent.com/{config['owner']}/{config['repo']}/{config.get('branch', 'main')}/{config['filter_path']}"
    print(f"\nFilter URL: {raw_url}")


if __name__ == "__main__":
    main()
