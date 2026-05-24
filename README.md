# AdGuard Filter Sync

Multi-device push → shared pull for custom AdGuard filter rules via GitHub.

Any device pushes rules to a shared GitHub repo with **smart merge** — deduplication, redundant subdomain detection, conflict warnings, and sorted output. All AdGuard instances subscribe to the same raw URL and auto-update.

## Setup

### 1. Create the GitHub repo

```bash
gh repo create adguard-filters --public --clone
# or create it at https://github.com/new
```

Copy `filter.txt` into the repo and push it.

### 2. Configure

```bash
cp config.example.json config.json
cp .env.example .env
```

Edit `config.json`:
```json
{
    "owner": "your-github-username",
    "repo": "adguard-filters",
    "filter_path": "filter.txt",
    "branch": "main"
}
```

Edit `.env`:
```
GITHUB_TOKEN=ghp_your_token_here
```

Get a token at https://github.com/settings/tokens with `repo` scope (private) or `public_repo` scope (public).

### 3. Subscribe in AdGuard

Add this URL as a custom filter in every AdGuard instance:

```
https://raw.githubusercontent.com/YOUR_USERNAME/adguard-filters/main/filter.txt
```

Set update interval to 1 hour (or whatever `! Expires:` says in the filter header).

## Usage

### Add/merge rules

```bash
# Python (any OS)
python push.py "||example.com^"
python push.py "||ads.example.com^" "@@||allowed.example.com^"

# PowerShell (Windows)
.\push.ps1 "||example.com^"

# Bash (Linux/Mac)
./push.sh "||example.com^"
```

### Merge from a file

```bash
python push.py --merge-file local_rules.txt
.\push.ps1 -MergeFile .\local_rules.txt
./push.sh --merge-file local_rules.txt
```

### Remove rules

```bash
python push.py --remove "||example.com^"
.\push.ps1 -Remove "||example.com^"
./push.sh --remove "||example.com^"
```

### List current rules (grouped by type)

```bash
python push.py --list
.\push.ps1 -List
./push.sh --list
```

### Pipe from stdin

```bash
echo "||example.com^" | python push.py --stdin
cat new_rules.txt | python push.py --stdin
```

### Options

| Flag | Python | PowerShell | Bash |
|------|--------|-----------|------|
| Don't sort | `--no-sort` | `-NoSort` | `--no-sort` |
| Force add redundant | `--force` | — | — |
| Custom commit msg | `-m "msg"` | `-Message "msg"` | `-m "msg"` |

## Smart Merge Behavior

The scripts don't blindly append. They:

1. **Deduplicate** — skips rules that already exist in the remote filter
2. **Detect redundant subdomains** — `||sub.example.com^` is skipped if `||example.com^` already blocks the parent domain
3. **Warn about conflicts** — alerts you if both a block rule and an exception exist for the same domain
4. **Sort by category** — organizes rules into blocks, exceptions, cosmetic, and other (disable with `--no-sort`)
5. **Retry on conflict** — if another device pushed simultaneously (SHA mismatch / HTTP 409), automatically re-fetches and re-merges up to 3 times

## How it works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Device A   │     │  Device B   │     │  Device C   │
│  push.py    │     │  push.ps1   │     │  push.sh    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────┬───────┴───────────────────┘
                   ▼
        ┌─────────────────────┐
        │   GitHub API        │
        │   (Contents API)    │
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │   filter.txt        │
        │   (raw.github.com)  │
        └──────────┬──────────┘
                   │
       ┌───────────┼───────────────────┐
       ▼           ▼                   ▼
┌────────────┐ ┌────────────┐  ┌────────────┐
│ AdGuard    │ │ AdGuard    │  │ AdGuard    │
│ Instance 1 │ │ Instance 2 │  │ Instance 3 │
└────────────┘ └────────────┘  └────────────┘
```

- **Push**: Any device uses the GitHub Contents API to update `filter.txt` (commit directly).
- **Pull**: All AdGuard instances poll the raw URL on their configured interval.
- **Dedup**: Scripts automatically skip duplicate rules.
- **Conflict-free**: The GitHub API uses SHA-based optimistic locking — if two devices push simultaneously, one will get a 409 and can retry.

## Deploy on each device

Just copy the scripts + config to each device. No git installation required — everything uses the GitHub REST API via `curl`/`urllib`/`Invoke-RestMethod`.

Minimum requirements per platform:
- **Windows**: PowerShell 5+ (built-in) or Python 3
- **Linux/Mac**: bash + curl, or Python 3
- **Android (Termux)**: Python 3
- **iOS (a]Shell/iSH)**: Python 3
