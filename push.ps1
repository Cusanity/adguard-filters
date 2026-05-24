<#
.SYNOPSIS
    Push AdGuard filter rules to a shared GitHub-hosted filter list with smart merge.
.DESCRIPTION
    Merges rules intelligently: deduplicates, detects redundant subdomain rules,
    warns about conflicts, sorts by category, and retries on concurrent edit conflicts.
.EXAMPLE
    .\push.ps1 "||example.com^"
    .\push.ps1 "||ads.example.com^" "@@||allowed.example.com^"
    .\push.ps1 -Remove "||example.com^"
    .\push.ps1 -List
    .\push.ps1 -MergeFile .\local_rules.txt
#>
param(
    [Parameter(Position = 0, ValueFromRemainingArguments)]
    [string[]]$Rules,

    [switch]$Remove,
    [switch]$List,
    [switch]$NoSort,
    [string]$MergeFile,
    [string]$Message
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MaxRetries = 3
$RetryDelay = 2

# Load config
$configPath = Join-Path $ScriptDir "config.json"
if (-not (Test-Path $configPath)) {
    Write-Error "config.json not found. Copy config.example.json and fill in your details."
    exit 1
}
$config = Get-Content $configPath | ConvertFrom-Json

# Get token
$token = $env:GITHUB_TOKEN
if (-not $token) {
    $envFile = Join-Path $ScriptDir ".env"
    if (Test-Path $envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match "^GITHUB_TOKEN=(.+)$") {
                $token = $Matches[1].Trim().Trim('"').Trim("'")
            }
        }
    }
}
if (-not $token) {
    Write-Error "GITHUB_TOKEN not found. Set it as environment variable or in .env file."
    exit 1
}

$owner = $config.owner
$repo = $config.repo
$filterPath = $config.filter_path
$branch = if ($config.branch) { $config.branch } else { "main" }

$headers = @{
    "Authorization"        = "Bearer $token"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

function Get-FilterFile {
    $url = "https://api.github.com/repos/$owner/$repo/contents/$filterPath`?ref=$branch"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    $content = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($response.content))
    return @{ Content = $content; Sha = $response.sha }
}

function Update-FilterFile($content, $sha, $commitMsg) {
    $updateUrl = "https://api.github.com/repos/$owner/$repo/contents/$filterPath"
    $body = @{
        message = $commitMsg
        content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
        sha     = $sha
        branch  = $branch
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $updateUrl -Headers $headers -Method Put -Body $body -ContentType "application/json" | Out-Null
        return $true
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 409) {
            return $false
        }
        throw
    }
}

function Split-Filter($content) {
    $lines = $content -split "`n"
    $headerLines = @()
    $ruleLines = @()
    $headerDone = $false

    foreach ($line in $lines) {
        if (-not $headerDone -and ($line.StartsWith("!") -or $line.Trim() -eq "")) {
            $headerLines += $line
        }
        else {
            $headerDone = $true
            $ruleLines += $line
        }
    }
    return @{ Header = $headerLines; Rules = $ruleLines }
}

function Get-Domain($rule) {
    if ($rule -match '^(?:@@)?\|\|([a-zA-Z0-9\-_.]+)\^(\$.*)?$') {
        return $Matches[1].ToLower()
    }
    return $null
}

function Test-Redundant($existingRules, $newRule) {
    if ($newRule.StartsWith("@@")) { return $null }
    $domain = Get-Domain $newRule
    if (-not $domain) { return $null }

    $existingDomains = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($r in $existingRules) {
        if (-not $r.StartsWith("@@")) {
            $d = Get-Domain $r
            if ($d) { [void]$existingDomains.Add($d) }
        }
    }

    $parts = $domain.Split(".")
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $parent = ($parts[$i..($parts.Count - 1)]) -join "."
        if ($existingDomains.Contains($parent)) {
            return "||$parent^"
        }
    }
    return $null
}

function Get-Category($rule) {
    if ($rule.StartsWith("@@")) { return "exception" }
    if ($rule -match '##|#@#|#\$#|#%#') { return "cosmetic" }
    if ($rule.StartsWith("||") -or $rule.StartsWith("|") -or $rule.StartsWith("*")) { return "block" }
    return "other"
}

# Collect rules from arguments and file
$allRules = @()
if ($Rules) { $allRules += $Rules }
if ($MergeFile) {
    if (-not (Test-Path $MergeFile)) {
        Write-Error "File not found: $MergeFile"
        exit 1
    }
    Get-Content $MergeFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("!")) {
            $allRules += $line
        }
    }
}

# Fetch current file
$file = Get-FilterFile
$content = $file.Content
$sha = $file.Sha

if ($List) {
    $parsed = Split-Filter $content
    $rules_list = $parsed.Rules | Where-Object { $_.Trim() }
    if ($rules_list) {
        $blocks = $rules_list | Where-Object { (Get-Category $_) -eq "block" }
        $exceptions = $rules_list | Where-Object { (Get-Category $_) -eq "exception" }
        $cosmetic = $rules_list | Where-Object { (Get-Category $_) -eq "cosmetic" }
        $other = $rules_list | Where-Object { (Get-Category $_) -eq "other" }

        Write-Host "Current rules ($($rules_list.Count) total):"
        if ($blocks) {
            Write-Host "`n  Block rules ($($blocks.Count)):"
            $blocks | ForEach-Object { Write-Host "    $_" }
        }
        if ($exceptions) {
            Write-Host "`n  Exception rules ($($exceptions.Count)):"
            $exceptions | ForEach-Object { Write-Host "    $_" }
        }
        if ($cosmetic) {
            Write-Host "`n  Cosmetic rules ($($cosmetic.Count)):"
            $cosmetic | ForEach-Object { Write-Host "    $_" }
        }
        if ($other) {
            Write-Host "`n  Other rules ($($other.Count)):"
            $other | ForEach-Object { Write-Host "    $_" }
        }
    }
    else {
        Write-Host "No rules yet."
    }
    exit 0
}

if (-not $allRules -or $allRules.Count -eq 0) {
    Write-Host "Usage: .\push.ps1 [-Remove] [-List] [-MergeFile <path>] [-NoSort] [-Message <msg>] <rule1> [rule2] ..."
    exit 1
}

# Retry loop for concurrent edit handling
for ($attempt = 0; $attempt -lt $MaxRetries; $attempt++) {
    if ($attempt -gt 0) {
        Write-Host "  (conflict detected, retrying in ${RetryDelay}s...)"
        Start-Sleep -Seconds $RetryDelay
        $file = Get-FilterFile
        $content = $file.Content
        $sha = $file.Sha
    }

    $parsed = Split-Filter $content

    # Update timestamp
    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'")
    $headerLines = $parsed.Header | ForEach-Object {
        if ($_.StartsWith("! Last modified:")) { "! Last modified: $now" } else { $_ }
    }

    $existingRules = $parsed.Rules | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
    $existingSet = [System.Collections.Generic.HashSet[string]]::new()
    $existingRules | ForEach-Object { [void]$existingSet.Add($_) }

    if ($Remove) {
        $removeSet = [System.Collections.Generic.HashSet[string]]::new()
        $allRules | ForEach-Object { [void]$removeSet.Add($_.Trim()) }

        $removed = @()
        $kept = @()
        foreach ($line in $parsed.Rules) {
            if ($removeSet.Contains($line.Trim())) {
                $removed += $line.Trim()
            }
            else {
                $kept += $line
            }
        }

        if ($removed.Count -eq 0) {
            Write-Host "No matching rules found to remove."
            exit 0
        }

        $newContent = ($headerLines + $kept) -join "`n"
        if (-not $newContent.EndsWith("`n")) { $newContent += "`n" }

        $commitMsg = if ($Message) { $Message } else { "Remove $($removed.Count) rule(s)" }
        $success = Update-FilterFile $newContent $sha $commitMsg

        if ($success) {
            Write-Host "Removed $($removed.Count) rule(s):"
            $removed | ForEach-Object { Write-Host "  - $_" }
            break
        }
    }
    else {
        # Smart merge
        $added = @()
        $skipped = @()
        $redundant = @()

        foreach ($rule in $allRules) {
            $r = $rule.Trim()
            if (-not $r) { continue }
            if ($existingSet.Contains($r)) {
                $skipped += $r
                continue
            }
            # Check redundancy
            $coveredBy = Test-Redundant $existingRules $r
            if ($coveredBy) {
                $redundant += @{ Rule = $r; CoveredBy = $coveredBy }
                continue
            }
            $added += $r
            [void]$existingSet.Add($r)
        }

        if ($added.Count -eq 0) {
            if ($skipped) {
                Write-Host "Skipped $($skipped.Count) duplicate(s):"
                $skipped | ForEach-Object { Write-Host "  = $_" }
            }
            if ($redundant) {
                Write-Host "Skipped $($redundant.Count) redundant rule(s):"
                $redundant | ForEach-Object { Write-Host "  ~ $($_.Rule)  (covered by $($_.CoveredBy))" }
            }
            Write-Host "Nothing new to merge."
            exit 0
        }

        # Merge and sort
        $mergedRules = @($existingRules) + @($added)

        if (-not $NoSort) {
            $blocks = $mergedRules | Where-Object { (Get-Category $_) -eq "block" } | Sort-Object
            $exceptions = $mergedRules | Where-Object { (Get-Category $_) -eq "exception" } | Sort-Object
            $cosmetic = $mergedRules | Where-Object { (Get-Category $_) -eq "cosmetic" } | Sort-Object
            $otherR = $mergedRules | Where-Object { (Get-Category $_) -eq "other" } | Sort-Object
            $mergedRules = @()
            if ($blocks) { $mergedRules += $blocks }
            if ($exceptions) { $mergedRules += $exceptions }
            if ($cosmetic) { $mergedRules += $cosmetic }
            if ($otherR) { $mergedRules += $otherR }
        }

        $newContent = ($headerLines + $mergedRules) -join "`n"
        if (-not $newContent.EndsWith("`n")) { $newContent += "`n" }

        $commitMsg = if ($Message) { $Message } else { "Merge $($added.Count) rule(s)" }
        $success = Update-FilterFile $newContent $sha $commitMsg

        if ($success) {
            Write-Host "Merged $($added.Count) rule(s):"
            $added | ForEach-Object { Write-Host "  + $_" }
            if ($skipped.Count -gt 0) {
                Write-Host "Skipped $($skipped.Count) duplicate(s):"
                $skipped | ForEach-Object { Write-Host "  = $_" }
            }
            if ($redundant.Count -gt 0) {
                Write-Host "Skipped $($redundant.Count) redundant rule(s):"
                $redundant | ForEach-Object { Write-Host "  ~ $($_.Rule)  (covered by $($_.CoveredBy))" }
            }
            break
        }
    }
}

if (-not $success -and $attempt -eq $MaxRetries) {
    Write-Error "Max retries exceeded due to concurrent edits."
    exit 1
}

$rawUrl = "https://raw.githubusercontent.com/$owner/$repo/$branch/$filterPath"
Write-Host "`nFilter URL: $rawUrl"
