# AdGuard Filter Sync

Automatically syncs custom AdGuard filter rules across all devices via a shared GitHub-hosted filter list.

- **Push**: Each device reads its local AdGuard user rules and commits them to GitHub.
- **Pull**: Every AdGuard instance subscribes to the raw GitHub URL and auto-updates on its poll interval.

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Each device runs sync_daemon.py (scheduled every 30 min)   │
│                                                             │
│  1. Read local AdGuard user rules from DB                   │
│  2. Fetch filter.txt from GitHub                            │
│  3. Merge new rules in (dedup, sort)                        │
│  4. Push back to GitHub if anything changed                 │
└────────────────────────┬────────────────────────────────────┘
                         │  GitHub Contents API
                         ▼
              ┌─────────────────────┐
              │  filter.txt         │  ← single source of truth
              │  (raw.github.com)   │
              └──────────┬──────────┘
                         │  AdGuard subscription URL (auto-poll)
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    AdGuard Win    AdGuard Mac    AdGuard Home
```

---

## One-time setup (do this once, shared across all devices)

### 1. Create the GitHub repo

The repo already exists at: `https://github.com/Cusanity/adguard-filters`

If setting up from scratch:
```bash
gh repo create adguard-filters --public --clone
```

### 2. Get a GitHub token

Go to https://github.com/settings/tokens → **Fine-grained token** or **Classic token** with `repo` scope (or `public_repo` for public repos).

### 3. Configure

`config.json` is **gitignored** (it's machine-specific). Create it from the example on each device:

```bash
cp config.example.json config.json
```

`config.json` — shared settings (safe to keep locally, do **not** commit):
```json
{
    "owner": "Cusanity",
    "repo": "adguard-filters",
    "filter_path": "filter.txt",
    "branch": "master"
}
```
The `owner`/`repo`/`filter_path`/`branch` fields are the same on every device. Only add `adguard_flm_db` (Windows/macOS) or `adguard_home_*` (Linux) if auto-detection fails — see `config.example.json` for all options.

`.env` — secret, never commit:
```
GITHUB_TOKEN=ghp_your_token_here
```

### 4. Subscribe in AdGuard

Add this as a **custom filter subscription** in every AdGuard instance:
```
https://raw.githubusercontent.com/Cusanity/adguard-filters/master/filter.txt
```
Set the update interval to **1 hour**.

---

## Per-device setup (repeat on each machine)

Copy the repo folder to the device, configure it, then install the scheduler for that platform.

### Windows — AdGuard for Windows

**Requirements:** Python 3, AdGuard for Windows installed

**Auto-sync daemon:**
```powershell
# Run as Administrator
.\install_task.ps1                  # installs Scheduled Task, runs every 30 min
.\install_task.ps1 -RunNow          # test immediately
.\install_task.ps1 -IntervalMinutes 15   # custom interval
.\install_task.ps1 -Uninstall       # remove
```

**Local AdGuard DB path (auto-detected):**
```
C:\ProgramData\Adguard\FLM\agflm_standard.db
```
Table: `rules_list`, column: `rules_text`, where `filter_id = -2147483648`

**Manual push:**
```powershell
python push.py "||example.com^"
python push.py --list
python push.py --remove "||example.com^"
```

---

### macOS — AdGuard for Mac

**Requirements:** Python 3, AdGuard for Mac installed

**Auto-sync daemon:**
```bash
chmod +x install_launchd.sh
./install_launchd.sh                 # installs launchd agent, runs every 30 min
./install_launchd.sh --run-now       # test immediately
./install_launchd.sh --interval 15   # custom interval (minutes)
./install_launchd.sh --uninstall     # remove
```

**Local AdGuard DB path (auto-detected, tried in order):**
```
~/Library/Group Containers/TC3Q7MAJXF.com.adguard.mac/Library/Application Support/FLM/agflm_standard.db
~/Library/Group Containers/TC3Q7MAJXF.com.adguard.mac/Library/Application Support/filters/agflm_standard.db
~/Library/Application Support/AdGuard/FLM/agflm_standard.db
~/Library/Application Support/AdGuard/filters/agflm_standard.db
~/Library/Application Support/com.adguard.mac.adguard/FLM/agflm_standard.db
~/Library/Application Support/com.adguard.mac.adguard/filters/agflm_standard.db
```
If none found, locate it yourself and set `"adguard_flm_db"` in `config.json`:
```bash
find ~/Library -name "agflm_standard.db" 2>/dev/null
```

**Manual push:**
```bash
python3 push.py "||example.com^"
./push.sh "||example.com^"
```

---

### Linux — AdGuard Home

**Requirements:** Python 3, AdGuard Home running

**Auto-sync daemon:**
```bash
chmod +x install_cron.sh
./install_cron.sh                    # installs cron job, runs every 30 min
./install_cron.sh --run-now          # test immediately
./install_cron.sh --interval 15      # custom interval
./install_cron.sh --uninstall        # remove
```

**Add AdGuard Home connection to `config.json`:**
```json
{
    "owner": "Cusanity",
    "repo": "adguard-filters",
    "filter_path": "filter.txt",
    "branch": "master",
    "adguard_home_url": "http://localhost:3000",
    "adguard_home_user": "admin",
    "adguard_home_password": "yourpassword"
}
```
The daemon hits `GET /control/filtering/get_rules` on the AdGuard Home REST API.
If the API is unreachable, it falls back to reading `AdGuardHome.yaml` directly from these paths (tried in order):
```
~/AdGuardHome/AdGuardHome.yaml
/opt/AdGuardHome/AdGuardHome.yaml
/etc/adguardhome/AdGuardHome.yaml
/var/lib/adguardhome/AdGuardHome.yaml
```
Override with `"adguard_home_yaml": "/your/path/AdGuardHome.yaml"` in `config.json`.

**Manual push:**
```bash
python3 push.py "||example.com^"
./push.sh "||example.com^"
```

---

### iOS / Android

No daemon possible. These devices are **pull-only** — they subscribe to the filter URL and receive all rules automatically.

If you need to push a rule from a mobile device, use [Working Copy](https://workingcopyapp.com/) (iOS) or Termux (Android):
```bash
python push.py "||example.com^"
```

---

## Push rules manually (any platform)

```bash
# Add rules
python push.py "||ads.example.com^"
python push.py "||a.com^" "@@||allowed.com^"

# Read from file
python push.py --merge-file local_rules.txt

# Remove a rule
python push.py --remove "||ads.example.com^"

# List all current rules
python push.py --list

# Read from stdin
echo "||ads.example.com^" | python push.py --stdin
```

| Flag | Description |
|------|-------------|
| `--remove` | Remove instead of add |
| `--list` | List all rules grouped by type |
| `--stdin` | Read rules from stdin |
| `--merge-file FILE` | Merge rules from a local file |
| `--no-sort` | Don't sort rules by category |
| `-m "msg"` | Custom git commit message |

---

## Smart merge behavior

Rules are never blindly appended. The scripts always:

1. **Deduplicate** — skip rules already in the filter
2. **Detect redundant subdomains** — skip `||sub.example.com^` if `||example.com^` already exists
3. **Warn on conflicts** — alert if a block and exception exist for the same domain
4. **Sort by category** — blocks → exceptions → cosmetic → other
5. **Retry on conflict** — if two devices push simultaneously (HTTP 409), re-fetch and re-merge up to 3 times

---

## Troubleshooting

**`sync_daemon.py` finds 0 rules**
- Windows: confirm `C:\ProgramData\Adguard\FLM\agflm_standard.db` exists and you've added at least one user rule in AdGuard's UI
- macOS: AdGuard may use a different group container path — set `"adguard_flm_db"` in `config.json`
- Linux: confirm AdGuard Home is running and the URL/credentials in `config.json` are correct

**`ERROR: GITHUB_TOKEN not found`**
- Ensure `.env` exists with `GITHUB_TOKEN=ghp_...`
- On Windows the Scheduled Task uses `sync_runner.cmd` which is auto-generated by `install_task.ps1` and contains the token

**Rules appear in AdGuard but not on GitHub**
- Run `python sync_daemon.py` manually and check the output / configured log file

**Log location:** defaults to `sync.log` next to the scripts. Override it with `log_dir` or `log_path` in `config.json`.
