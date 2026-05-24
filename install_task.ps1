<#
.SYNOPSIS
    Install/uninstall the AdGuard Filter Sync scheduled task.
    Must be run as Administrator.

.EXAMPLE
    # Install (runs every 30 minutes)
    .\install_task.ps1

    # Install with custom interval
    .\install_task.ps1 -IntervalMinutes 15

    # Uninstall
    .\install_task.ps1 -Uninstall

    # Run sync immediately (test)
    .\install_task.ps1 -RunNow
#>
param(
    [int]$IntervalMinutes = 30,
    [switch]$Uninstall,
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"
$TaskName = "AdGuard Filter Sync"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SyncScript = Join-Path $ScriptDir "sync_daemon.py"
$ConfigFile = Join-Path $ScriptDir "config.json"
$EnvFile = Join-Path $ScriptDir ".env"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell → Run as Administrator."
    exit 1
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task '$TaskName' removed."
    }
    else {
        Write-Host "Task '$TaskName' not found."
    }
    exit 0
}

if ($RunNow) {
    Write-Host "Running sync now..."
    # Find Python
    $python = Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }
    if (-not $python) {
        Write-Error "Python not found in PATH."
        exit 1
    }

    # Load token from .env for the environment
    $env:GITHUB_TOKEN = ""
    if (Test-Path $EnvFile) {
        Get-Content $EnvFile | ForEach-Object {
            if ($_ -match "^GITHUB_TOKEN=(.+)$") {
                $env:GITHUB_TOKEN = $Matches[1].Trim().Trim('"').Trim("'")
            }
        }
    }

    & $python $SyncScript
    exit $LASTEXITCODE
}

# --- Install ---

# Verify prerequisites
if (-not (Test-Path $SyncScript)) {
    Write-Error "sync_daemon.py not found at: $SyncScript"
    exit 1
}
if (-not (Test-Path $ConfigFile)) {
    Write-Error "config.json not found. Copy config.example.json and configure it first."
    exit 1
}
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env not found. Copy .env.example and add your GITHUB_TOKEN."
    exit 1
}

# Find Python executable
$python = Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}
if (-not $python) {
    Write-Error "Python not found. Install Python and ensure it's in PATH."
    exit 1
}

# Read token from .env
$githubToken = ""
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match "^GITHUB_TOKEN=(.+)$") {
            $githubToken = $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
}
if (-not $githubToken) {
    Write-Error "GITHUB_TOKEN not found in .env file."
    exit 1
}

# Remove existing task if present
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed existing task."
}

# Create the scheduled task
$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$SyncScript`"" `
    -WorkingDirectory $ScriptDir

# Run every N minutes
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 9999)

# Run as SYSTEM with highest privileges (can read AdGuard's locked DB)
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

# SYSTEM needs the GITHUB_TOKEN as an environment variable
# We'll create a wrapper script that sets it
$wrapperPath = Join-Path $ScriptDir "sync_runner.cmd"
$wrapperContent = @"
@echo off
set "GITHUB_TOKEN=$githubToken"
"$python" "$SyncScript"
"@
Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII

# Update action to use the wrapper
$action = New-ScheduledTaskAction `
    -Execute $wrapperPath `
    -WorkingDirectory $ScriptDir

$task = Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Syncs AdGuard user rules to GitHub every $IntervalMinutes minutes"

# Restrict wrapper file permissions (contains token)
$acl = Get-Acl $wrapperPath
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl -Path $wrapperPath -AclObject $acl

Write-Host ""
Write-Host "Installed scheduled task: '$TaskName'" -ForegroundColor Green
Write-Host "  Interval: every $IntervalMinutes minutes"
Write-Host "  Runs as: SYSTEM (can read locked AdGuard DB)"
Write-Host "  Python: $python"
Write-Host "  Script: $SyncScript"
Write-Host "  Wrapper: $wrapperPath (permissions restricted)"
Write-Host ""
Write-Host "To test immediately: .\install_task.ps1 -RunNow"
Write-Host "To remove: .\install_task.ps1 -Uninstall"
Write-Host ""
Write-Host "The task will:"
Write-Host "  1. Read user rules from AdGuard's database"
Write-Host "  2. Merge with existing rules on GitHub"
Write-Host "  3. Push any new rules to the shared filter"
Write-Host ""
Write-Host "Make sure AdGuard subscribes to your filter URL:"
$config = Get-Content $ConfigFile | ConvertFrom-Json
$branch = if ($config.branch) { $config.branch } else { "main" }
Write-Host "  https://raw.githubusercontent.com/$($config.owner)/$($config.repo)/$branch/$($config.filter_path)" -ForegroundColor Cyan
