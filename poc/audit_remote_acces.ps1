# =============================================================================
# audit_remote_access.ps1
# Colonial Pipeline / DarkSide Ransomware Incident — 2021
# Remote Access Account Exposure Auditor
#
# Identifies accounts matching the conditions that enabled Colonial Pipeline's
# initial breach: remote access accounts with no MFA, stale passwords, or
# long periods of inactivity that retain VPN/remote access group membership.
#
# Sourced from: CISA Advisory AA21-131A recommendations
# Reference:    https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a
#
# Usage:
#   .\audit_remote_access.ps1
#   .\audit_remote_access.ps1 -InactiveDays 60 -PasswordAgeDays 180
#   .\audit_remote_access.ps1 -GroupNames "VPN Users","Remote Workers"
#
# Requirements: PowerShell 5.1+, RSAT ActiveDirectory module
#               Run as domain user with AD read access
# Safety:       Read-only. No accounts are modified.
# =============================================================================

param(
    [int]$InactiveDays    = 90,
    [int]$PasswordAgeDays = 365,
    [string[]]$GroupNames = @("VPN Users", "Remote Access Users",
                               "DirectAccess Users", "Always On VPN")
)

# ── Output helpers ─────────────────────────────────────────────────────────────

$script:HighRisk = 0
$script:MedRisk  = 0

function Write-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow; $script:MedRisk++ }
function Write-High  { param($m) Write-Host "[HIGH]  $m" -ForegroundColor Red;    $script:HighRisk++ }

# ── Banner ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " Remote Access Account Exposure Auditor"                    -ForegroundColor White
Write-Host " Colonial Pipeline / DarkSide — CISA AA21-131A Guidance"   -ForegroundColor Gray
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"                -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host " Checking for accounts matching Colonial Pipeline breach conditions:"
Write-Host "   - Remote access group membership + no recent login"
Write-Host "   - Passwords older than $PasswordAgeDays days"
Write-Host "   - Enabled accounts inactive > $InactiveDays days"
Write-Host ""

# ── Check for ActiveDirectory module ──────────────────────────────────────────

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[!!] ActiveDirectory module not found." -ForegroundColor Red
    Write-Host "     Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$cutoffLogin    = (Get-Date).AddDays(-$InactiveDays)
$cutoffPassword = (Get-Date).AddDays(-$PasswordAgeDays)

# ── 1. Scan remote access groups ───────────────────────────────────────────────

Write-Info "Scanning remote access groups for stale or risky accounts..."
Write-Host ""

$riskReport = @()

foreach ($groupName in $GroupNames) {
    Write-Info "Checking group: $groupName"

    try {
        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" }
    } catch {
        Write-Warn "Group '$groupName' not found or not accessible: $_"
        continue
    }

    if (-not $members) {
        Write-Ok "Group '$groupName' has no members"
        continue
    }

    Write-Info "  Members found: $($members.Count)"

    foreach ($member in $members) {
        try {
            $user = Get-ADUser $member.SamAccountName -Properties `
                LastLogonDate, PasswordLastSet, Enabled, `
                PasswordNeverExpires, PasswordExpired, `
                Description, EmailAddress -ErrorAction SilentlyContinue

            if (-not $user) { continue }

            $risk    = "Low"
            $reasons = @()

            # Account enabled but never logged in or stale
            if ($user.Enabled -and (
                    $user.LastLogonDate -eq $null -or
                    $user.LastLogonDate -lt $cutoffLogin)) {
                $risk = "High"
                $days = if ($user.LastLogonDate) {
                    [int]((Get-Date) - $user.LastLogonDate).TotalDays
                } else { "Never" }
                $reasons += "Inactive $days days"
            }

            # Password older than threshold
            if ($user.PasswordLastSet -lt $cutoffPassword) {
                if ($risk -ne "High") { $risk = "Medium" }
                $pwDays = [int]((Get-Date) - $user.PasswordLastSet).TotalDays
                $reasons += "Password $pwDays days old"
            }

            # Password never expires (often indicates service accounts)
            if ($user.PasswordNeverExpires) {
                if ($risk -ne "High") { $risk = "Medium" }
                $reasons += "Password never expires"
            }

            # Disabled account still in remote access group
            if (-not $user.Enabled) {
                $risk = "High"
                $reasons += "Account DISABLED but still in remote access group"
            }

            if ($risk -ne "Low") {
                $riskReport += [PSCustomObject]@{
                    Risk            = $risk
                    Group           = $groupName
                    Username        = $user.SamAccountName
                    DisplayName     = $user.Name
                    LastLogin       = if ($user.LastLogonDate) {
                                          $user.LastLogonDate.ToString("yyyy-MM-dd")
                                      } else { "Never" }
                    PasswordLastSet = if ($user.PasswordLastSet) {
                                          $user.PasswordLastSet.ToString("yyyy-MM-dd")
                                      } else { "Unknown" }
                    Enabled         = $user.Enabled
                    Reasons         = $reasons -join "; "
                }
            }
        } catch {
            Write-Warn "Could not query user $($member.SamAccountName): $_"
        }
    }
}

# ── 2. Display results ─────────────────────────────────────────────────────────

Write-Host ""

if ($riskReport.Count -eq 0) {
    Write-Ok "No high or medium risk accounts found in remote access groups"
} else {
    Write-Host " Risk findings:" -ForegroundColor White
    Write-Host ""

    $highRiskAccounts = $riskReport | Where-Object { $_.Risk -eq "High" }
    $medRiskAccounts  = $riskReport | Where-Object { $_.Risk -eq "Medium" }

    if ($highRiskAccounts) {
        Write-Host " HIGH RISK — Immediate action required:" -ForegroundColor Red
        $highRiskAccounts | Sort-Object LastLogin |
            Format-Table Risk, Group, Username, DisplayName, LastLogin,
                         PasswordLastSet, Enabled, Reasons -AutoSize
        $script:HighRisk += $highRiskAccounts.Count
    }

    if ($medRiskAccounts) {
        Write-Host " MEDIUM RISK — Review within 48 hours:" -ForegroundColor Yellow
        $medRiskAccounts | Sort-Object LastLogin |
            Format-Table Risk, Group, Username, DisplayName, LastLogin,
                         PasswordLastSet, Enabled, Reasons -AutoSize
        $script:MedRisk += $medRiskAccounts.Count
    }
}

# ── 3. Check for recently created remote access accounts ───────────────────────

Write-Info "Checking for remote access accounts created in the last 30 days..."

$recentCutoff = (Get-Date).AddDays(-30)
$recentAccounts = @()

foreach ($groupName in $GroupNames) {
    try {
        Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq "user" } |
            ForEach-Object {
                $u = Get-ADUser $_.SamAccountName -Properties Created, Enabled `
                    -ErrorAction SilentlyContinue
                if ($u -and $u.Created -gt $recentCutoff) {
                    $recentAccounts += [PSCustomObject]@{
                        Group    = $groupName
                        Username = $u.SamAccountName
                        Created  = $u.Created.ToString("yyyy-MM-dd")
                        Enabled  = $u.Enabled
                    }
                }
            }
    } catch {}
}

if ($recentAccounts) {
    Write-Warn "Recently created remote access accounts (verify these are authorized):"
    $recentAccounts | Format-Table -AutoSize
} else {
    Write-Ok "No remote access accounts created in the last 30 days"
}

# ── Summary ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " SUMMARY"                                                    -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($script:HighRisk -gt 0) {
    Write-Host " !! HIGH RISK accounts found: $($script:HighRisk)" -ForegroundColor Red
    Write-Host ""
    Write-Host " Immediate actions (per CISA AA21-131A):"
    Write-Host "   1. Disable or remove inactive accounts from remote access groups"
    Write-Host "   2. Enforce MFA on ALL remote access accounts — no exceptions"
    Write-Host "   3. Force password resets on accounts with passwords > $PasswordAgeDays days"
    Write-Host "   4. Verify all active accounts belong to current employees"
    Write-Host "   5. Check credentials against known breach datasets (HaveIBeenPwned API)"
} elseif ($script:MedRisk -gt 0) {
    Write-Host " Medium risk accounts found: $($script:MedRisk)" -ForegroundColor Yellow
    Write-Host " Review and remediate within 48 hours per CISA guidance"
} else {
    Write-Host " No high or medium risk accounts identified" -ForegroundColor Green
}

Write-Host ""
Write-Host " Reference: CISA Advisory AA21-131A — DarkSide Ransomware" -ForegroundColor Gray
Write-Host " Incident:  Colonial Pipeline, May 2021"                   -ForegroundColor Gray
Write-Host " Root cause: Inactive VPN account, no MFA, reused credential" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
