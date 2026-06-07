# =============================================================================
# scan_darkside_iocs.ps1
# Colonial Pipeline / DarkSide Ransomware Incident — 2021
# DarkSide IOC & Ransomware Artifact Scanner
#
# Scans a Windows host for indicators of compromise sourced from:
#   CISA Advisory AA21-131A (DarkSide Ransomware)
#   CISA Malware Analysis Report AR21-189A (DarkSide samples)
#
# Checks for:
#   - Known DarkSide file hashes in common staging directories
#   - Ransom note artifacts (README.*.TXT pattern)
#   - Volume Shadow Copy status (absence may indicate VSS deletion)
#   - Known DarkSide C2 references in DNS cache and hosts file
#   - Suspicious process execution (vssadmin, rclone, 7z in unusual contexts)
#   - Windows Event Log entries for shadow copy deletion
#
# References:
#   https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a
#   https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-189a
#
# Usage:
#   .\scan_darkside_iocs.ps1
#   .\scan_darkside_iocs.ps1 -ScanEvents -EventLookbackDays 30
#   .\scan_darkside_iocs.ps1 -ScanPath "D:\"
#
# Requirements: PowerShell 5.1+. Run as Administrator for full visibility.
# Safety:       Read-only. No system modifications are made.
# =============================================================================

param(
    [switch]$ScanEvents        = $false,
    [int]$EventLookbackDays    = 14,
    [string]$ScanPath          = "C:\"
)

# ── IOCs from CISA AA21-131A and AR21-189A ────────────────────────────────────

# File hashes — sourced from CISA MAR AR21-189A
# https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-189a
$knownMaliciousHashes = @{
    "3a40f17091eff3c065e01f2cf4dcd4f2effc3b6e62f5ef69c5cad3f0a44a7ee4" = "DarkSide ransomware sample (CISA AR21-189A)"
    "9cee5522a7ca2bfca7cd3d9daba23e9a30deb6205f56c12045839075f7627297" = "DarkSide ransomware sample (CISA AR21-189A)"
    "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f" = "DarkSide ransomware sample (CISA AR21-189A)"
    "3c81d3b4e4a0cc470b4daa3a5af8d73e3fa21a7e74cb7b76d3cbf5d0e8da23a3" = "DarkSide PowerShell tool (CISA AR21-189A)"
}

# C2 IPs and domains — sourced from CISA AA21-131A
$knownC2IPs = @(
    "198.199.40.90",
    "198.199.35.224"
)

$knownC2Domains = @(
    "temisleyes.com",
    "catsdegree.com"
)

# Directories to check for malicious files
$scanDirs = @(
    "$env:TEMP",
    "$env:SystemRoot\Temp",
    "$env:ProgramData",
    "$env:APPDATA",
    "C:\Users\Public"
)

# ── Output helpers ─────────────────────────────────────────────────────────────

$script:Compromised = 0
$script:Warnings    = 0

function Write-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow; $script:Warnings++ }
function Write-Issue { param($m) Write-Host "[!!]    $m" -ForegroundColor Red;    $script:Compromised++ }

# ── Banner ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " DarkSide IOC Scanner — Colonial Pipeline Incident 2021"   -ForegroundColor White
Write-Host " Sources: CISA AA21-131A / CISA MAR AR21-189A"             -ForegroundColor Gray
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"                -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

# ── 1. Known file hash check ───────────────────────────────────────────────────

Write-Info "Checking for known DarkSide file hashes (CISA AR21-189A)..."
Write-Info "Scanning directories: $($scanDirs -join ', ')"

$hashHit = $false
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $hash = (Get-FileHash $_.FullName -Algorithm SHA256 `
                    -ErrorAction SilentlyContinue).Hash.ToLower()
                if ($hash -and $knownMaliciousHashes.ContainsKey($hash)) {
                    Write-Issue "KNOWN DARKSIDE HASH MATCH: $($_.FullName)"
                    Write-Issue "  SHA-256: $hash"
                    Write-Issue "  Source:  $($knownMaliciousHashes[$hash])"
                    $hashHit = $true
                }
            } catch {}
        }
}
if (-not $hashHit) {
    Write-Ok "No known DarkSide file hashes found in scanned directories"
}

Write-Host ""

# ── 2. Ransom note artifacts ───────────────────────────────────────────────────

Write-Info "Searching for DarkSide ransom note artifacts (README.*.TXT)..."

$ransomNotes = Get-ChildItem -Path $ScanPath -Recurse `
    -Filter "README.*.TXT" -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 50000 }  # ransom notes are small text files

if ($ransomNotes) {
    foreach ($note in $ransomNotes) {
        Write-Issue "Ransom note pattern found: $($note.FullName)"
        Write-Issue "  Size: $($note.Length) bytes | Modified: $($note.LastWriteTime)"
        # Show first line only — for context, not content reproduction
        $firstLine = Get-Content $note.FullName -TotalCount 1 -ErrorAction SilentlyContinue
        if ($firstLine) {
            Write-Issue "  First line: $($firstLine.Substring(0, [Math]::Min(60, $firstLine.Length)))..."
        }
    }
} else {
    Write-Ok "No ransom note artifacts found"
}

Write-Host ""

# ── 3. Volume Shadow Copy status ───────────────────────────────────────────────

Write-Info "Checking Volume Shadow Copy status..."
Write-Info "(VSS deletion via vssadmin.exe is a near-universal pre-ransomware action)"

try {
    $vssOutput = & vssadmin list shadows 2>&1
    if ($vssOutput -match "No items found" -or $vssOutput -match "successfully") {
        if ($vssOutput -match "No items found") {
            Write-Warn "No shadow copies found — this may indicate VSS deletion by ransomware"
            Write-Warn "  Verify: was VSS intentionally disabled on this host?"
            Write-Warn "  Check Event Log for: vssadmin delete shadows"
        } else {
            $count = ($vssOutput | Select-String "Shadow Copy ID").Count
            Write-Ok "Shadow copies present ($count found) — VSS appears intact"
        }
    }
} catch {
    Write-Warn "Could not query VSS status: $_"
}

Write-Host ""

# ── 4. DNS cache and hosts file — C2 domain check ─────────────────────────────

Write-Info "Checking DNS cache and hosts file for known DarkSide C2 domains..."
Write-Info "C2 domains (CISA AA21-131A): $($knownC2Domains -join ', ')"

$c2DnsHit = $false

# Windows DNS resolver cache
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($domain in $knownC2Domains) {
        $hit = $dnsCache | Where-Object { $_.Entry -like "*$domain*" }
        if ($hit) {
            Write-Issue "C2 domain found in DNS cache: $domain"
            $hit | ForEach-Object {
                Write-Issue "  Entry: $($_.Entry) → $($_.Data)"
            }
            $c2DnsHit = $true
        }
    }
} catch {
    Write-Warn "Could not query DNS cache: $_"
}

# Hosts file check
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    foreach ($domain in $knownC2Domains) {
        if ($hostsContent -match $domain) {
            Write-Issue "C2 domain found in hosts file: $domain"
            $c2DnsHit = $true
        }
    }
}

if (-not $c2DnsHit) {
    Write-Ok "No known DarkSide C2 domains found in DNS cache or hosts file"
    Write-Info "  Note: DNS cache is ephemeral — check SIEM/proxy logs for historical lookups"
}

Write-Host ""

# ── 5. Active network connections to known C2 IPs ─────────────────────────────

Write-Info "Checking active connections to known DarkSide C2 IPs..."
Write-Info "C2 IPs (CISA AA21-131A): $($knownC2IPs -join ', ')"

$c2ConnHit = $false
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($ip in $knownC2IPs) {
        $hit = $connections | Where-Object { $_.RemoteAddress -eq $ip }
        if ($hit) {
            Write-Issue "ACTIVE connection to known DarkSide C2 IP: $ip"
            $hit | ForEach-Object {
                Write-Issue "  Local: $($_.LocalAddress):$($_.LocalPort) → Remote: $($_.RemoteAddress):$($_.RemotePort)"
                Write-Issue "  PID: $($_.OwningProcess)"
            }
            $c2ConnHit = $true
        }
    }
} catch {
    Write-Warn "Could not enumerate network connections: $_"
}

if (-not $c2ConnHit) {
    Write-Ok "No active connections to known DarkSide C2 IPs"
}

Write-Host ""

# ── 6. Suspicious tool execution check ────────────────────────────────────────

Write-Info "Checking for suspicious processes associated with DarkSide TTPs..."

# Check for Rclone running (used for exfiltration in DarkSide attacks)
$rclone = Get-Process -Name "rclone" -ErrorAction SilentlyContinue
if ($rclone) {
    Write-Warn "Rclone process running — verify this is authorized:"
    $rclone | Select-Object Id, Name, Path, StartTime | Format-Table -AutoSize
} else {
    Write-Ok "Rclone not currently running"
}

# Check for unusual 7-Zip usage (archiving prior to exfiltration)
$sevenZip = Get-Process -Name "7z","7za","7zG" -ErrorAction SilentlyContinue
if ($sevenZip) {
    Write-Warn "7-Zip process running — verify this is authorized compression activity:"
    $sevenZip | Select-Object Id, Name, Path | Format-Table -AutoSize
}

Write-Host ""

# ── 7. Optional Event Log scan ─────────────────────────────────────────────────

if ($ScanEvents) {
    Write-Info "Scanning Windows Event Log (last $EventLookbackDays days)..."
    $startTime = (Get-Date).AddDays(-$EventLookbackDays)

    # Event 4688: Process creation — look for vssadmin delete shadows
    Write-Info "  Checking for shadow copy deletion events (Event 4688)..."
    try {
        $vssEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4688; StartTime=$startTime
        } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "vssadmin" -and $_.Message -match "delete" }

        if ($vssEvents) {
            Write-Issue "Shadow copy deletion detected in Event Log ($($vssEvents.Count) events):"
            $vssEvents | Select-Object -First 5 | ForEach-Object {
                Write-Issue "  $($_.TimeCreated) — $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))"
            }
        } else {
            Write-Ok "No shadow copy deletion events found in Security log"
        }
    } catch {
        Write-Warn "Could not query Security log — run as Administrator"
    }

    # Event 4688: Rclone or 7z execution
    Write-Info "  Checking for exfiltration tool execution events..."
    try {
        $exfilEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4688; StartTime=$startTime
        } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "rclone|7za\.exe|7z\.exe" }

        if ($exfilEvents) {
            Write-Warn "Exfiltration tool execution detected ($($exfilEvents.Count) events):"
            $exfilEvents | Select-Object -First 3 | ForEach-Object {
                Write-Warn "  $($_.TimeCreated) — $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))"
            }
        } else {
            Write-Ok "No Rclone/7-Zip execution events in Security log"
        }
    } catch {
        Write-Warn "Could not query process creation events"
    }

    Write-Host ""
}

# ── Summary ────────────────────────────────────────────────────────────────────

Write-Host "============================================================" -ForegroundColor White
Write-Host " SCAN SUMMARY"                                               -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($script:Compromised -gt 0) {
    Write-Host " !! $($script:Compromised) CRITICAL INDICATOR(S) FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host " Immediate response actions:"
    Write-Host "   1. Isolate this host from the network immediately"
    Write-Host "   2. Preserve memory and disk before any remediation"
    Write-Host "   3. Contact your incident response team"
    Write-Host "   4. Report to CISA: https://www.cisa.gov/report"
    Write-Host "   5. Notify FBI: https://www.ic3.gov"
} elseif ($script:Warnings -gt 0) {
    Write-Host " ⚠  $($script:Warnings) warning(s) — investigate before clearing" -ForegroundColor Yellow
} else {
    Write-Host " ✓  No DarkSide indicators found on this host" -ForegroundColor Green
}

Write-Host ""
Write-Host " IOC sources: CISA AA21-131A + MAR AR21-189A"              -ForegroundColor Gray
Write-Host " Incident:    Colonial Pipeline ransomware attack, May 2021" -ForegroundColor Gray
Write-Host " Tip: Re-run with -ScanEvents for Event Log analysis"       -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
