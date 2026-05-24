#!/usr/bin/env bash
# AdGuard Filter Sync - Push rules to a shared GitHub-hosted filter list with smart merge.
#
# Merges rules intelligently: deduplicates, detects redundant subdomain rules,
# sorts by category, and retries on concurrent edit conflicts.
#
# Usage:
#   ./push.sh "||example.com^"
#   ./push.sh "||ads.example.com^" "@@||allowed.example.com^"
#   ./push.sh --remove "||example.com^"
#   ./push.sh --list
#   echo "||example.com^" | ./push.sh --stdin
#   ./push.sh --merge-file local_rules.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_RETRIES=3
RETRY_DELAY=2

# Load config (try python3 first, fall back to jq)
CONFIG_FILE="$SCRIPT_DIR/config.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config.json not found. Copy config.example.json and fill in your details." >&2
    exit 1
fi

if command -v python3 &>/dev/null; then
    read_config() { python3 -c "import json; c=json.load(open('$CONFIG_FILE')); print(c.get('$1','$2'))" 2>/dev/null; }
else
    read_config() { jq -r ".$1 // \"$2\"" "$CONFIG_FILE"; }
fi

OWNER=$(read_config owner "")
REPO=$(read_config repo "")
FILTER_PATH=$(read_config filter_path "filter.txt")
BRANCH=$(read_config branch "main")

# Get token
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    ENV_FILE="$SCRIPT_DIR/.env"
    if [[ -f "$ENV_FILE" ]]; then
        GITHUB_TOKEN=$(grep '^GITHUB_TOKEN=' "$ENV_FILE" | cut -d= -f2- | tr -d "\"'")
        export GITHUB_TOKEN
    fi
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "ERROR: GITHUB_TOKEN not found. Set it as environment variable or in .env file." >&2
    exit 1
fi

# Parse arguments
ACTION="add"
RULES=()
USE_STDIN=false
COMMIT_MSG=""
NO_SORT=false
MERGE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remove) ACTION="remove"; shift ;;
        --list) ACTION="list"; shift ;;
        --stdin) USE_STDIN=true; shift ;;
        --no-sort) NO_SORT=true; shift ;;
        --merge-file|-f) MERGE_FILE="$2"; shift 2 ;;
        -m|--message) COMMIT_MSG="$2"; shift 2 ;;
        *) RULES+=("$1"); shift ;;
    esac
done

if [[ "$USE_STDIN" == true ]]; then
    while IFS= read -r line; do
        [[ -n "${line// /}" ]] && RULES+=("$line")
    done
fi

if [[ -n "$MERGE_FILE" ]]; then
    if [[ ! -f "$MERGE_FILE" ]]; then
        echo "ERROR: File not found: $MERGE_FILE" >&2
        exit 1
    fi
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"  # trim leading
        line="${line%"${line##*[![:space:]]}"}"  # trim trailing
        [[ -n "$line" && ! "$line" == "!"* ]] && RULES+=("$line")
    done < "$MERGE_FILE"
fi

# --- Helper: fetch file from GitHub ---
fetch_file() {
    local api_url="https://api.github.com/repos/$OWNER/$REPO/contents/$FILTER_PATH?ref=$BRANCH"
    RESPONSE=$(curl -sf -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$api_url")

    FILE_SHA=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['sha'])" 2>/dev/null || \
               echo "$RESPONSE" | jq -r '.sha')
    FILE_CONTENT=$(echo "$RESPONSE" | python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
print(base64.b64decode(data['content']).decode('utf-8'), end='')" 2>/dev/null || \
        echo "$RESPONSE" | jq -r '.content' | base64 -d)
}

# --- Helper: push file to GitHub, returns 0 on success, 1 on conflict ---
push_file() {
    local new_content="$1"
    local msg="$2"
    local encoded_content
    encoded_content=$(echo -n "$new_content" | base64 | tr -d '\n')
    local update_url="https://api.github.com/repos/$OWNER/$REPO/contents/$FILTER_PATH"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$update_url" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "{\"message\":$(echo -n "$msg" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"$msg\""),\"content\":\"$encoded_content\",\"sha\":\"$FILE_SHA\",\"branch\":\"$BRANCH\"}")

    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
        return 0
    elif [[ "$http_code" == "409" ]]; then
        return 1
    else
        echo "ERROR: GitHub API returned HTTP $http_code" >&2
        exit 1
    fi
}

# --- Helper: extract domain from rule ---
extract_domain() {
    local rule="$1"
    echo "$rule" | sed -n 's/^@@//; s/^||\([a-zA-Z0-9._-]*\)\^.*$/\1/p' | tr '[:upper:]' '[:lower:]'
}

# --- Helper: check if rule is redundant (subdomain of existing block) ---
is_redundant() {
    local rule="$1"
    shift
    local existing_domains=("$@")

    # Skip exception rules
    [[ "$rule" == @@* ]] && return 1

    local domain
    domain=$(extract_domain "$rule")
    [[ -z "$domain" ]] && return 1

    local parts
    IFS='.' read -ra parts <<< "$domain"
    local num_parts=${#parts[@]}

    for ((i=1; i<num_parts-1; i++)); do
        local parent="${parts[*]:$i}"
        parent="${parent// /.}"
        for existing in "${existing_domains[@]}"; do
            if [[ "$existing" == "$parent" ]]; then
                REDUNDANT_PARENT="||${parent}^"
                return 0
            fi
        done
    done
    return 1
}

# --- List ---
if [[ "$ACTION" == "list" ]]; then
    fetch_file
    echo "Current rules:"
    echo "$FILE_CONTENT" | grep -v '^!' | grep -v '^$' | sort | while read -r line; do
        echo "  $line"
    done
    exit 0
fi

if [[ ${#RULES[@]} -eq 0 ]]; then
    echo "Usage: ./push.sh [--remove|--list|--stdin|--merge-file <file>|--no-sort] [-m message] <rule1> [rule2] ..."
    exit 1
fi

# --- Main push loop with retry ---
for ((attempt=0; attempt<MAX_RETRIES; attempt++)); do
    if [[ $attempt -gt 0 ]]; then
        echo "  (conflict detected, retrying in ${RETRY_DELAY}s...)"
        sleep "$RETRY_DELAY"
    fi

    fetch_file

    # Split header and body
    HEADER=$(echo "$FILE_CONTENT" | awk '/^!/{print; next} /^$/ && !body{print; next} {body=1; exit}')
    BODY=$(echo "$FILE_CONTENT" | awk 'BEGIN{body=0} /^!/{if(!body) next} /^$/{if(!body) next} {body=1; print}')

    # Update timestamp
    NOW=$(date -u +"%Y-%m-%d %H:%M UTC")
    HEADER=$(echo "$HEADER" | sed "s/^! Last modified:.*$/! Last modified: $NOW/")

    # Collect existing rules and domains
    mapfile -t EXISTING_RULES < <(echo "$BODY" | grep -v '^$' || true)
    declare -A EXISTING_SET=()
    EXISTING_DOMAINS=()
    for r in "${EXISTING_RULES[@]}"; do
        r_trimmed="${r#"${r%%[![:space:]]*}"}"
        r_trimmed="${r_trimmed%"${r_trimmed##*[![:space:]]}"}"
        [[ -n "$r_trimmed" ]] && EXISTING_SET["$r_trimmed"]=1
        local_domain=$(extract_domain "$r_trimmed")
        [[ -n "$local_domain" && ! "$r_trimmed" == @@* ]] && EXISTING_DOMAINS+=("$local_domain")
    done

    if [[ "$ACTION" == "remove" ]]; then
        REMOVED=()
        NEW_BODY="$BODY"
        for rule in "${RULES[@]}"; do
            rule_trimmed="${rule#"${rule%%[![:space:]]*}"}"
            rule_trimmed="${rule_trimmed%"${rule_trimmed##*[![:space:]]}"}"
            if echo "$NEW_BODY" | grep -qxF "$rule_trimmed"; then
                NEW_BODY=$(echo "$NEW_BODY" | grep -vxF "$rule_trimmed")
                REMOVED+=("$rule_trimmed")
            fi
        done

        if [[ ${#REMOVED[@]} -eq 0 ]]; then
            echo "No matching rules found to remove."
            exit 0
        fi

        NEW_CONTENT=$(printf "%s\n%s\n" "$HEADER" "$NEW_BODY")
        MSG="${COMMIT_MSG:-Remove ${#REMOVED[@]} rule(s)}"

        if push_file "$NEW_CONTENT" "$MSG"; then
            echo "Removed ${#REMOVED[@]} rule(s):"
            for r in "${REMOVED[@]}"; do
                echo "  - $r"
            done
            break
        fi
    else
        # Smart merge
        ADDED=()
        SKIPPED=()
        REDUNDANT_INFO=()

        for rule in "${RULES[@]}"; do
            rule_trimmed="${rule#"${rule%%[![:space:]]*}"}"
            rule_trimmed="${rule_trimmed%"${rule_trimmed##*[![:space:]]}"}"
            [[ -z "$rule_trimmed" ]] && continue

            # Check duplicate
            if [[ -n "${EXISTING_SET[$rule_trimmed]:-}" ]]; then
                SKIPPED+=("$rule_trimmed")
                continue
            fi

            # Check redundancy
            REDUNDANT_PARENT=""
            if is_redundant "$rule_trimmed" "${EXISTING_DOMAINS[@]}"; then
                REDUNDANT_INFO+=("$rule_trimmed (covered by $REDUNDANT_PARENT)")
                continue
            fi

            ADDED+=("$rule_trimmed")
            EXISTING_SET["$rule_trimmed"]=1
        done

        if [[ ${#ADDED[@]} -eq 0 ]]; then
            if [[ ${#SKIPPED[@]} -gt 0 ]]; then
                echo "Skipped ${#SKIPPED[@]} duplicate(s):"
                for r in "${SKIPPED[@]}"; do echo "  = $r"; done
            fi
            if [[ ${#REDUNDANT_INFO[@]} -gt 0 ]]; then
                echo "Skipped ${#REDUNDANT_INFO[@]} redundant rule(s):"
                for r in "${REDUNDANT_INFO[@]}"; do echo "  ~ $r"; done
            fi
            echo "Nothing new to merge."
            exit 0
        fi

        # Merge rules
        ALL_RULES=("${EXISTING_RULES[@]}" "${ADDED[@]}")

        if [[ "$NO_SORT" == false ]]; then
            # Sort by category
            SORTED_RULES=$(printf "%s\n" "${ALL_RULES[@]}" | sort -f)
            NEW_BODY="$SORTED_RULES"
        else
            NEW_BODY=$(printf "%s\n" "${ALL_RULES[@]}")
        fi

        NEW_CONTENT=$(printf "%s\n%s\n" "$HEADER" "$NEW_BODY")
        MSG="${COMMIT_MSG:-Merge ${#ADDED[@]} rule(s)}"

        if push_file "$NEW_CONTENT" "$MSG"; then
            echo "Merged ${#ADDED[@]} rule(s):"
            for r in "${ADDED[@]}"; do echo "  + $r"; done
            if [[ ${#SKIPPED[@]} -gt 0 ]]; then
                echo "Skipped ${#SKIPPED[@]} duplicate(s):"
                for r in "${SKIPPED[@]}"; do echo "  = $r"; done
            fi
            if [[ ${#REDUNDANT_INFO[@]} -gt 0 ]]; then
                echo "Skipped ${#REDUNDANT_INFO[@]} redundant rule(s):"
                for r in "${REDUNDANT_INFO[@]}"; do echo "  ~ $r"; done
            fi
            break
        fi
    fi
done

if [[ $attempt -eq $MAX_RETRIES ]]; then
    echo "ERROR: Max retries exceeded due to concurrent edits." >&2
    exit 1
fi

RAW_URL="https://raw.githubusercontent.com/$OWNER/$REPO/$BRANCH/$FILTER_PATH"
echo ""
echo "Filter URL: $RAW_URL"
