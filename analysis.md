# Colonial Pipeline — DarkSide Ransomware Incident

> **Type:** Ransomware / Double Extortion / Critical Infrastructure Attack  
> **Severity:** Critical — National impact  
> **Affected organization:** Colonial Pipeline Company  
> **Attack date:** 2021-05-07 (ransomware deployment)  
> **Data exfiltration date:** 2021-05-06 (prior to ransomware)  
> **Operational impact:** 6-day shutdown of 5,500-mile fuel pipeline  
> **Attribution:** DarkSide RaaS affiliate (GOLD WATERFALL / Secureworks tracking)  
> **Incident class:** Ransomware-as-a-Service / Double Extortion / Critical Infrastructure

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Background](#background)
3. [Timeline](#timeline)
4. [Attack Chain](#attack-chain)
   - [Stage 0 — Initial Access: Compromised VPN Credential](#stage-0--initial-access-compromised-vpn-credential)
   - [Stage 1 — Reconnaissance and Lateral Movement](#stage-1--reconnaissance-and-lateral-movement)
   - [Stage 2 — Data Exfiltration (Double Extortion Pre-stage)](#stage-2--data-exfiltration-double-extortion-pre-stage)
   - [Stage 3 — Ransomware Deployment](#stage-3--ransomware-deployment)
   - [Stage 4 — Impact and Operational Shutdown](#stage-4--impact-and-operational-shutdown)
   - [Stage 5 — Ransom Payment and Partial Recovery](#stage-5--ransom-payment-and-partial-recovery)
5. [The Threat Actor: DarkSide / GOLD WATERFALL](#the-threat-actor-darkside--gold-waterfall)
6. [Evasion & Anti-Detection Techniques](#evasion--anti-detection-techniques)
7. [Attack Surface](#attack-surface)
8. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
9. [Detection](#detection)
10. [Proof of Concept](#proof-of-concept)
11. [Remediation](#remediation)
12. [Systemic Lessons](#systemic-lessons)
13. [References](#references)

---

## Executive Summary

Colonial Pipeline Company operates the largest refined petroleum pipeline system in the United States — 5,500 miles of pipeline carrying gasoline, diesel, and jet fuel from Houston, Texas to the New York Harbor area, supplying approximately 45 percent of fuel consumed on the East Coast. On May 7, 2021, Colonial shut down its entire pipeline in response to a ransomware attack on its IT network — the first time in the company's history that operational systems had been halted by a cyberattack. The shutdown lasted six days, triggering fuel shortages across 17 states, panic buying, price spikes to their highest level since 2014, and a federal emergency declaration by the Biden administration.

The attack was carried out by an affiliate of DarkSide, a ransomware-as-a-service (RaaS) platform operated by the cybercriminal group tracked as GOLD WATERFALL by Secureworks. DarkSide's developers built and maintained the ransomware infrastructure; their affiliate — the unnamed actor who conducted the Colonial Pipeline intrusion — rented access to that infrastructure and executed the attack independently. DarkSide received a share of the ransom payment; the affiliate kept the remainder. This RaaS model is significant because it separates the technical sophistication of ransomware development from the operational execution of attacks, enabling cybercriminals with limited development capability to conduct devastating intrusions using professional-grade tooling.

The initial access vector was a single compromised credential for a legacy VPN account that was no longer in active use but had not been deprovisioned. The account lacked multi-factor authentication. No vulnerability was exploited — no CVE, no zero-day, no phishing campaign that succeeded against a vigilant user. A username and password found in a previously leaked credential dataset was sufficient to gain authenticated access to Colonial's network. From that entry point, the attacker conducted reconnaissance, moved laterally across the IT network, exfiltrated approximately 100 GB of data over roughly 24 hours, and then deployed DarkSide ransomware against multiple systems simultaneously.

The OT network — the industrial control systems that physically operate the pipeline — was never directly compromised by the ransomware. Colonial's decision to shut down pipeline operations was a precautionary business decision made because the company could not confirm the safety of operating the pipeline while its billing and IT systems were encrypted and unavailable. This distinction matters: the attack demonstrated that ransomware against an organization's IT network can force shutdown of OT operations through business logic alone, without any attacker touching the control systems. Colonial paid approximately $4.4 million USD in Bitcoin within hours of the attack; the US Department of Justice subsequently recovered approximately $2.3 million of that payment by seizing the Bitcoin wallet.

---

## Background

### Colonial Pipeline Company

Colonial Pipeline Company is the operator of the largest refined petroleum products pipeline system in the United States. The pipeline runs 5,500 miles from refineries in Houston, Texas to Linden, New Jersey, carrying gasoline, diesel, home heating oil, jet fuel, and military fuels to markets throughout the South and East Coast. The system has a capacity of 2.5 million barrels per day and serves approximately 50 million consumers. Its customers include airports, the US military, and commercial fuel distributors across 14 states plus the District of Columbia. The pipeline was constructed in the 1960s and is so foundational to East Coast fuel supply that it is formally designated as critical infrastructure under US law.

Colonial's IT network managed billing, operational coordination, and business systems. The OT network — running SCADA and industrial control systems — managed the physical operation of pumps, valves, flow meters, and the pipeline itself. These networks were connected but segregated. Understanding this architecture is essential to understanding the attack's impact: the ransomware never reached the OT network, yet the pipeline still shut down for six days.

### The DarkSide RaaS Model

DarkSide emerged publicly in August 2020, operated by GOLD WATERFALL (Secureworks tracking name). It operated as a ransomware-as-a-service platform in which GOLD WATERFALL developed, maintained, and hosted the ransomware infrastructure and affiliate portal, then recruited and vetted cybercriminal affiliates who paid to use the platform to conduct attacks. Affiliates received between 75 and 90 percent of ransom proceeds depending on the ransom amount; GOLD WATERFALL kept the remainder. This model enabled GOLD WATERFALL to scale their operation across many simultaneous targets without conducting attacks themselves.

DarkSide implemented double extortion: before deploying ransomware, affiliates were required to exfiltrate victim data to DarkSide-controlled servers. Victims then faced two simultaneous threats — pay to receive a decryption key, or have the stolen data published on DarkSide's public data leak site. DarkSide maintained a professional public image, operating a press center, maintaining a no-targeting policy for hospitals and schools, and even making a widely publicized donation of $20,000 in Bitcoin to charity in October 2020 — a deliberate PR strategy to portray the group as principled criminals rather than indiscriminate destructors.

### The Threat Actor: DarkSide / GOLD WATERFALL

GOLD WATERFALL is assessed by Secureworks with high confidence to be an experienced cybercriminal group that previously operated as an affiliate of GOLD SOUTHFIELD's REvil ransomware before developing DarkSide independently. Darkside ransomware shares several architectural similarities with REvil and GandCrab, suggesting the developer is familiar with those families. The group advertises exclusively in Russian and requires affiliates to speak Russian. GOLD WATERFALL explicitly prohibits affiliates from targeting organizations in Commonwealth of Independent States (CIS) countries — a standard operational security measure adopted by Russian-speaking cybercriminal groups operating with implicit state tolerance.

The Colonial Pipeline attack was not executed by GOLD WATERFALL directly but by one of their vetted affiliates. The affiliate that attacked Colonial Pipeline is believed by US law enforcement to be connected to the individual later arrested by Russia's FSB in January 2022, when Russian authorities announced the takedown of REvil and arrested 14 individuals including one described by US officials as the actor responsible for the Colonial Pipeline attack. DarkSide itself announced it was shutting down on May 14, 2021 — one week after the Colonial attack — claiming its servers had been seized and its cryptocurrency wallets drained. Security researchers assessed this as likely a rebrand rather than a genuine shutdown; the group subsequently appeared to resurface as BlackMatter, and later infrastructure overlaps were identified with BlackCat/ALPHV.

---

## Timeline

```
2020-08-??   — DarkSide ransomware publicly debuts; GOLD WATERFALL begins operations
2020-11-??   — DarkSide launches its RaaS affiliate program on underground forums
2021-??-??   — Affiliate acquires compromised Colonial Pipeline VPN credential
               (likely from a dark web credential marketplace or prior breach dump)
2021-05-06   — Affiliate begins reconnaissance and lateral movement on Colonial IT network
2021-05-06   — ~100 GB of data exfiltrated to DarkSide-controlled servers over ~2 hours
               (double extortion pre-stage — data theft before ransomware deployment)
2021-05-07   — DarkSide ransomware deployed against Colonial IT network
               Colonial discovers the attack and shuts down the pipeline proactively
               Colonial engages Mandiant (then FireEye) for incident response
               Colonial notifies FBI
2021-05-07   — Colonial pays ~$4.4 million USD in Bitcoin to DarkSide affiliate
               (75 BTC at the time; ransom paid the same day as discovery)
2021-05-08   — US federal emergency declared; DOT waives hours-of-service regulations
               for fuel transport drivers in 17 states
2021-05-09   — Colonial states it plans to substantially restore operations by end of week
2021-05-10   — CISA and FBI publish Joint Cybersecurity Advisory AA21-131A
               IOCs shared with critical infrastructure partners
2021-05-12   — Colonial Pipeline resumes full operations
2021-05-13   — Colonial CEO Joseph Blount testifies to Senate that MFA was not enabled
               on the compromised VPN account
2021-05-14   — DarkSide announces shutdown of operations; claims servers seized
               and cryptocurrency wallets emptied by unknown third party
2021-06-07   — US DOJ announces recovery of ~$2.3M USD (63.7 BTC) from ransom payment
               by seizing the DarkSide affiliate's Bitcoin wallet
2021-07-08   — CISA publishes updated AA21-131A with DarkSide malware analysis IOCs
               CISA publishes Malware Analysis Report AR21-189A (DarkSide samples)
2022-01-14   — Russian FSB arrests 14 individuals linked to REvil, including one
               US officials assess conducted the Colonial Pipeline attack
```

**Key detail:** The entire intrusion from initial access to ransomware deployment took approximately 24–48 hours. The attacker moved quickly once inside — exfiltrating 100 GB of data and staging ransomware before Colonial's security team detected anything. The ransom was paid the same day the attack was discovered.

---

## Attack Chain

### Stage 0 — Initial Access: Compromised VPN Credential

The attacker gained entry to Colonial's network through a single compromised username and password for a legacy VPN profile. The account was no longer in active use — Colonial's CEO stated in Senate testimony that it was not believed the account was actively being used at the time of the intrusion — but it had not been deprovisioned. The account was not protected by multi-factor authentication. The credential appears to have been sourced from a previously leaked credential dataset; Mandiant (Colonial's incident response firm) found the same password in a separate batch of leaked credentials on the dark web, suggesting it had been harvested in a prior, unrelated breach and was being reused.

```
Attack entry point:
  Legacy VPN account (decommissioned but not deleted)
    → No MFA enforcement on VPN authentication
    → Credential found in dark web breach dump
    → Single factor (username + password) sufficient for network access
    → Attacker authenticates as legitimate remote user
    → Full network access granted per VPN profile permissions
```

**Critical detail:** No vulnerability was exploited. No CVE was involved. No phishing email needed to succeed. A username and a reused password — artifacts of inadequate credential hygiene — were the entire initial access mechanism. This makes Colonial Pipeline one of the clearest illustrations in public record of how sophisticated operational impact can flow from a completely elementary security failure.

### Stage 1 — Reconnaissance and Lateral Movement

Once authenticated to the VPN, the attacker conducted reconnaissance of the Colonial IT network. Based on the CISA advisory and Mandiant's findings, the attacker used tools consistent with DarkSide affiliate tradecraft: legitimate remote administration utilities, credential harvesting tools to collect additional account credentials from the network, and standard network enumeration techniques. The goal of this phase was to identify high-value targets — systems containing sensitive data for exfiltration and systems whose encryption would cause maximum operational disruption.

```
Post-access activity:
  Authenticated VPN session
    → Network enumeration (identifying hosts, shares, domain structure)
    → Credential harvesting (collecting additional account credentials)
    → Lateral movement to additional systems
    → Identification of data repositories (for exfiltration targeting)
    → Identification of critical IT systems (for ransomware targeting)
```

**Critical detail:** The CISA advisory (AA21-131A) documents that tools observed in DarkSide intrusions include legitimate administrative tools such as Cobalt Strike (used as a post-exploitation framework), Mimikatz (credential harvesting), and various remote desktop utilities. Critically, these are tools that appear in many legitimate IT environments — using them does not require introducing clearly malicious software until the final ransomware deployment stage. This "living off the land" and legitimate-tool-abuse approach significantly complicates detection.

### Stage 2 — Data Exfiltration (Double Extortion Pre-stage)

Before deploying ransomware, the attacker exfiltrated approximately 100 GB of data from Colonial's network to DarkSide-controlled servers. This exfiltration took approximately two hours. The data exfiltrated included business-sensitive information that DarkSide would subsequently threaten to publish unless Colonial paid. This is the "double extortion" mechanic: the victim faces simultaneous pressure to pay for a decryption key (to restore encrypted systems) and to prevent public release of stolen data (to avoid regulatory, competitive, and reputational damage from the leak).

```
Double extortion pre-stage:
  Attacker identifies sensitive data repositories
    → Archives data using 7-Zip or similar compression tool
    → Exfiltrates ~100 GB to DarkSide-controlled cloud infrastructure
    → Data staged on DarkSide leak site — held as leverage
    → Exfiltration complete BEFORE ransomware is deployed
    → At this point: even if ransomware is stopped, data is already stolen
```

**Critical detail:** Exfiltration is the most forensically detectable phase of a double extortion attack — moving 100 GB of data off-network generates anomalous traffic that well-tuned SIEM rules and DLP tools would flag. The fact that Colonial's security team did not detect the exfiltration before the ransomware ran suggests the monitoring coverage on egress traffic was insufficient. By the time ransomware alerts fired, the leverage was already in the attacker's hands.

### Stage 3 — Ransomware Deployment

With reconnaissance complete, lateral movement accomplished, and data already exfiltrated, the attacker deployed DarkSide ransomware simultaneously across multiple Colonial IT systems. DarkSide ransomware is a 64-bit Windows executable, compiled in C++, that uses a combination of RSA-1024 and Salsa20 encryption. It encrypts files on local drives and networked shares, appends a custom extension to encrypted files, and drops a ransom note in each affected directory.

```
Ransomware execution:
  DarkSide binary deployed to target systems
    → Terminates processes that could lock files:
        database services, backup agents, antivirus processes
    → Deletes Volume Shadow Copies (VSS) to prevent recovery
        via: vssadmin.exe delete shadows /all /quiet
    → Encrypts files using RSA-1024 (key exchange) + Salsa20 (file encryption)
    → Appends victim-specific extension to encrypted files
    → Drops ransom note: README.[victim_id].TXT in each directory
    → Reports completion to DarkSide C2 infrastructure
```

**Critical detail:** DarkSide ransomware explicitly excludes certain file types and directories from encryption to ensure the operating system remains bootable and the ransom note is accessible — an intentional design choice that reflects the RaaS model's interest in actually collecting ransom rather than causing pure destruction. The VSS deletion is the most forensically significant action: without shadow copies, file-level recovery without the decryption key becomes very difficult.

### Stage 4 — Impact and Operational Shutdown

Colonial's billing, operational coordination, and IT systems were encrypted. Colonial made the decision to proactively shut down pipeline operations — a decision made not because the pipeline control systems were compromised (they were not) but because the company could not safely operate the pipeline without its billing and operational IT systems functioning. Colonial also could not confirm the boundaries of the compromise, and shutting down the OT network was a precautionary measure to prevent any potential spread.

```
Operational impact chain:
  IT network encrypted
    → Billing systems offline (cannot measure or invoice fuel deliveries)
    → Operational coordination systems offline
    → Colonial cannot safely confirm OT network integrity
    → Colonial shuts down pipeline operations proactively
    → 5,500 miles of pipeline offline
    → ~45% of East Coast fuel supply disrupted
    → Fuel shortages in 17 states + DC
    → Average gas prices exceed $3/gallon (highest since 2014)
    → American Airlines reroutes flights due to jet fuel shortages at Charlotte Douglas
    → Biden administration declares federal emergency
    → DOT waives hours-of-service rules for fuel truck drivers in 17 states
```

**Critical detail:** The OT network was never directly attacked. CISA's advisory explicitly states: "At this time, there are no indications that the threat actor moved laterally to OT systems." The shutdown was a business decision, not a technical necessity forced by OT compromise. This is one of the most important lessons of the incident — ransomware against IT infrastructure can force shutdown of critical physical operations through business logic alone, without the attacker ever touching industrial control systems.

### Stage 5 — Ransom Payment and Partial Recovery

Colonial paid approximately $4.4 million USD (75 Bitcoin) to the DarkSide affiliate on May 7, 2021 — the same day the attack was discovered and the pipeline shut down. Colonial CEO Joseph Blount stated in Senate testimony that the decision to pay was made because the company did not know the extent of the damage and whether its backup systems would allow full recovery. The decryption tool provided by DarkSide was reportedly so slow that Colonial's own recovery efforts using backups ran faster — the decryptor was used as a supplementary measure rather than the primary recovery path.

On June 7, 2021, the US Department of Justice announced it had recovered approximately $2.3 million USD (63.7 BTC) of the ransom by seizing the Bitcoin wallet used by the affiliate to receive the payment. The DOJ obtained the private key to the wallet through a court-authorized seizure — demonstrating that cryptocurrency ransomware payments are not necessarily irreversible, and that law enforcement has developed capabilities to trace and seize cryptocurrency under certain conditions.

---

## The Threat Actor: DarkSide / GOLD WATERFALL

DarkSide operated as a professionally managed RaaS business. GOLD WATERFALL (Secureworks) / DarkSide maintained:

**Infrastructure:** A Tor-based data leak site for publishing stolen victim data, a content delivery network for hosting exfiltrated data, an affiliate portal for ransomware customization and deployment management, and automated payment processing with cryptocurrency mixing.

**Affiliate vetting:** DarkSide conducted interviews with prospective affiliates and required demonstrated technical competence. Affiliates could customize ransomware builds through the portal for specific targets. Affiliates kept 75–90% of ransom proceeds.

**Rules of engagement:** DarkSide publicly prohibited affiliates from targeting hospitals, schools, non-profits, government agencies, and organizations in CIS countries. This was both operational security (avoiding maximum law enforcement pressure) and brand management (positioning DarkSide as a "professional" criminal operation).

**Revenue split (documented):** Ransoms under $500,000 USD: affiliate keeps 80%, DarkSide keeps 20%. Ransoms over $5 million USD: affiliate keeps 90%, DarkSide keeps 10%.

**Post-Colonial shutdown:** On May 14, 2021, DarkSide announced cessation of operations, claiming servers had been seized and cryptocurrency balances had been emptied. Security researchers assessed this as likely a strategic rebranding. BlackMatter ransomware emerged shortly after with significant code and infrastructure overlaps. The FBI subsequently identified overlaps between BlackMatter, BlackCat/ALPHV, and DarkSide affiliates.

| Tracking name | Organization | Assessment |
|---------------|-------------|------------|
| GOLD WATERFALL | Secureworks | DarkSide operators; former REvil affiliate |
| DarkSide Group | Generic | Ransomware developers and RaaS platform operators |
| Unnamed affiliate | — | Conducted Colonial Pipeline intrusion; believed arrested by Russian FSB January 2022 |

---

## Evasion & Anti-Detection Techniques

DarkSide's evasion approach was methodical and reflected the professionalism of an experienced RaaS operation.

| Technique | Implementation | What it evades |
|-----------|---------------|----------------|
| Legitimate tool abuse | Used Cobalt Strike, Mimikatz, remote admin utilities rather than custom malware | Signature-based AV/EDR detection focused on known malicious binaries |
| Living off the land | Used built-in Windows tools (vssadmin, wmic, net) for VSS deletion and network enumeration | Behavioral detection rules that focus on third-party tool execution |
| Credential reuse via dark web | Used pre-harvested credential from breach dump rather than phishing | Email security controls, phishing detection |
| VPN authentication | Authenticated as a legitimate remote user via valid credentials | Network perimeter controls, firewall rules, IDS signatures |
| Pre-ransomware exfiltration | Data exfiltrated before ransomware deployed | Incident containment that focuses on stopping encryption rather than data loss |
| Ransomware binary customization | Affiliate-customized DarkSide build with victim-specific extension and C2 config | Generic DarkSide signatures (each build is unique) |
| VSS deletion | `vssadmin.exe delete shadows /all /quiet` before encryption | Shadow copy-based recovery |
| Process termination | Kills backup agents, database services before encryption | File locking preventing encryption of in-use files |
| Selective encryption | Excludes OS files and certain directories to keep system bootable | Complete system destruction that would prevent ransom payment |

**Key insight:** DarkSide's evasion strategy relied primarily on legitimacy — using valid credentials, legitimate administrative tools, and the VPN infrastructure that Colonial had built for its own staff. No novel anti-forensics technique was needed because the attacker looked like an authorized user until the ransomware fired. The correct mitigation is not signature-based detection but identity verification (MFA, credential hygiene) and behavioral monitoring (anomalous data movement, unusual process activity in administrative contexts).

---

## Attack Surface

The Colonial Pipeline attack surface was defined by organizational and operational decisions rather than technical vulnerabilities in software.

| Condition | Colonial Pipeline's state | Risk created |
|-----------|--------------------------|--------------|
| Legacy account deprovisioning | VPN account not deleted after going inactive | Single entry point requiring only a credential to exploit |
| MFA on remote access | Not enforced on all VPN accounts | Credential alone sufficient for authenticated network access |
| Credential hygiene | Password reused across services; credential appeared in breach dump | Dark web purchase or credential stuffing sufficient for access |
| Network segmentation | IT and OT networks connected but segregated | Ransomware on IT network did not spread to OT — segmentation worked |
| Egress monitoring | Insufficient to detect 100 GB exfiltration in time | Data theft completed before ransomware alerts fired |
| OT dependency on IT | Pipeline operations depended on billing/coordination IT systems | OT shutdown forced by IT compromise without OT ever being touched |
| Backup and recovery | Decryptor provided by attacker was slower than backup recovery | Backups existed but were not sufficient for rapid full recovery alone |

---

## Indicators of Compromise (IOCs)

The following IOCs are sourced from CISA Joint Advisory AA21-131A (updated July 8, 2021) and CISA Malware Analysis Report AR21-189A. These are the authoritative public IOC sources for the Colonial Pipeline / DarkSide incident.

### File Hashes (DarkSide Ransomware Samples — from CISA MAR AR21-189A)

| File description | Algorithm | Hash |
|-----------------|-----------|------|
| DarkSide ransomware sample (Windows x64) | SHA-256 | `3a40f17091eff3c065e01f2cf4dcd4f2effc3b6e62f5ef69c5cad3f0a44a7ee4` |
| DarkSide ransomware sample | SHA-256 | `9cee5522a7ca2bfca7cd3d9daba23e9a30deb6205f56c12045839075f7627297` |
| DarkSide ransomware sample | SHA-256 | `d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f` |
| DarkSide PowerShell script (tool) | SHA-256 | `3c81d3b4e4a0cc470b4daa3a5af8d73e3fa21a7e74cb7b76d3cbf5d0e8da23a3` |

### Network IOCs (from CISA AA21-131A)

| Type | Value | Description |
|------|-------|-------------|
| C2 domain | `temisleyes[.]com` | DarkSide C2 communication |
| C2 domain | `catsdegree[.]com` | DarkSide C2 communication |
| C2 IP | `198[.]199[.]40[.]90` | DarkSide C2 server |
| C2 IP | `198[.]199[.]35[.]224` | DarkSide C2 server |
| Tor hidden service | DarkSide leak site (`.onion`) | Data leak / victim communication (address rotated) |

> Note: All domains and IPs are defanged. Replace `[.]` with `.` for use in detection tools.

### Tools Observed (from CISA AA21-131A)

| Tool | Legitimate use | Malicious use in this incident |
|------|---------------|-------------------------------|
| Cobalt Strike | Penetration testing framework | Post-exploitation C2 and lateral movement |
| Mimikatz | Credential research tool | Credential harvesting from LSASS memory |
| 7-Zip | File compression | Archiving data for exfiltration |
| Rclone | Cloud sync utility | Exfiltrating data to cloud storage |
| PuTTy / PSCP | SSH client / file transfer | Network file transfer during exfiltration |
| vssadmin.exe | Windows built-in (VSS management) | Deleting shadow copies to prevent recovery |
| wmic.exe | Windows built-in (WMI interface) | Remote process execution |

### File System Artifacts

| OS | Artifact | Description |
|----|----------|-------------|
| Windows | `README.[victim_id].TXT` in each affected directory | DarkSide ransom note |
| Windows | Files with appended custom extension (e.g. `.darkside`) | DarkSide-encrypted files |
| Windows | Absence of shadow copies (`vssadmin list shadows` returns empty) | VSS deletion by ransomware pre-encryption |

### Registry

| Key | Description |
|-----|-------------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` | DarkSide may create entries here to persist or redirect process execution |
| Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) | Persistence mechanisms established during lateral movement phase |

---

## Detection

### Remote Access Account Audit (PowerShell)

Identifies VPN and remote access accounts that lack MFA enforcement and have not been used recently — replicating the exact condition that enabled Colonial's initial access. This is the highest-priority control given this incident.

```powershell
# Audit Active Directory accounts with remote access group membership
# Flag accounts inactive for > 90 days that retain group membership
# Requires ActiveDirectory module (RSAT)

Import-Module ActiveDirectory

$cutoffDate = (Get-Date).AddDays(-90)

# Find accounts in VPN/remote access groups that haven't logged on recently
$vpnGroups = @("VPN Users", "Remote Access", "DirectAccess Users")  # adjust for your environment

foreach ($group in $vpnGroups) {
    try {
        Get-ADGroupMember -Identity $group -Recursive |
            Where-Object { $_.objectClass -eq "user" } |
            ForEach-Object {
                Get-ADUser $_.SamAccountName -Properties LastLogonDate, Enabled, PasswordLastSet |
                    Where-Object {
                        ($_.LastLogonDate -lt $cutoffDate -or $_.LastLogonDate -eq $null) -and
                        $_.Enabled -eq $true
                    }
            } |
            Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, Enabled |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Could not query group: $group — $_"
    }
}
```

### DarkSide IOC Scanner (PowerShell)

Scans a Windows host for known DarkSide artifacts sourced from CISA advisory AA21-131A and Malware Analysis Report AR21-189A.

```powershell
# DarkSide IOC scanner — CISA AA21-131A / AR21-189A
# Checks file hashes, ransom note artifacts, VSS deletion evidence

$knownHashes = @(
    "3a40f17091eff3c065e01f2cf4dcd4f2effc3b6e62f5ef69c5cad3f0a44a7ee4",
    "9cee5522a7ca2bfca7cd3d9daba23e9a30deb6205f56c12045839075f7627297",
    "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f",
    "3c81d3b4e4a0cc470b4daa3a5af8d73e3fa21a7e74cb7b76d3cbf5d0e8da23a3"
)

Write-Host "[INFO] Checking for DarkSide ransom notes..." -ForegroundColor Cyan
$ransomNotes = Get-ChildItem -Path C:\ -Recurse -Filter "README.*.TXT" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 10000 }  # ransom notes are small text files

if ($ransomNotes) {
    $ransomNotes | ForEach-Object {
        Write-Host "[!!]  Ransom note found: $($_.FullName)" -ForegroundColor Red
    }
} else {
    Write-Host "[OK]  No ransom notes found" -ForegroundColor Green
}

Write-Host "[INFO] Checking Volume Shadow Copy status..." -ForegroundColor Cyan
$vss = vssadmin list shadows 2>&1
if ($vss -match "No items found") {
    Write-Host "[WARN] No shadow copies found — may indicate VSS deletion" -ForegroundColor Yellow
} else {
    Write-Host "[OK]  Shadow copies present" -ForegroundColor Green
}

Write-Host "[INFO] Checking for known DarkSide file hashes..." -ForegroundColor Cyan
Get-ChildItem -Path C:\Windows\Temp, $env:TEMP, C:\ProgramData `
    -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $knownHashes -contains $hash.ToLower()) {
                Write-Host "[!!]  KNOWN DARKSIDE HASH: $($_.FullName) ($hash)" -ForegroundColor Red
            }
        } catch {}
    }

Write-Host "[INFO] Checking network connections to known C2 IPs..." -ForegroundColor Cyan
$c2IPs = @("198.199.40.90", "198.199.35.224")
$c2IPs | ForEach-Object {
    $conn = Test-NetConnection -ComputerName $_ -Port 443 -InformationLevel Quiet `
        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($conn) {
        Write-Host "[!!]  Connection possible to C2: $_" -ForegroundColor Red
    }
}
```

### Anomalous Data Exfiltration (Splunk)

Detects large outbound data transfers consistent with the pre-ransomware exfiltration pattern — 100 GB over approximately two hours.

```splunk
| Detect large outbound data transfers (exfiltration pattern)
index=network_traffic direction=outbound
| bucket _time span=1h
| stats sum(bytes_out) as total_bytes_out by src_ip, dest_ip, _time
| eval GB_out = round(total_bytes_out / 1073741824, 2)
| where GB_out > 10
| sort - GB_out
| table _time, src_ip, dest_ip, GB_out

| Detect use of known exfiltration tools (Rclone, 7-Zip in unusual context)
index=endpoint_logs (process_name="rclone.exe" OR process_name="7z.exe" OR process_name="7za.exe")
NOT (user="backup_service" OR parent_process="backup_manager.exe")
| stats count by host, user, process_name, CommandLine, _time
| sort - _time
```

### VSS Deletion Detection (Splunk / KQL)

Detects vssadmin.exe shadow copy deletion — a near-universal pre-ransomware action.

```splunk
| Detect shadow copy deletion
index=windows EventCode=4688
(process_name="vssadmin.exe" OR CommandLine="*delete shadows*")
| stats count by host, user, CommandLine, _time
| where count > 0
```

```kql
// KQL — Microsoft Sentinel / Defender
DeviceProcessEvents
| where FileName =~ "vssadmin.exe"
    and ProcessCommandLine has_any ("delete", "shadows", "resize shadowstorage")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Cobalt Strike Beacon Detection (Splunk)

```splunk
| Detect Cobalt Strike default HTTPS beacon patterns
index=proxy_logs OR index=network_logs
| eval uri_len = len(uri)
| where uri_len > 200 AND (method="GET" OR method="POST")
| stats count by src_ip, dest_host, uri, user_agent
| where count > 20  | sort - count
```

---

## Proof of Concept

> **⚠️ For detection and educational purposes only.**  
> See the [`poc/`](./poc/) directory for full scripts.

### PoC 1: Remote Access Account Exposure Auditor

[`poc/audit_remote_access.ps1`](./poc/audit_remote_access.ps1) — A PowerShell script that audits Active Directory for remote access and VPN group members, flagging accounts that replicate the conditions present in the Colonial Pipeline breach: accounts inactive for more than a configurable threshold (default 90 days) that retain group membership and have no MFA status recorded. It also checks for accounts with passwords that have not changed in over a year, and produces a prioritized risk list sorted by last login date. Requires RSAT ActiveDirectory module. Outputs a color-coded report with a summary count of high-risk accounts and recommended immediate actions. Run as a domain user with read access to AD.

### PoC 2: DarkSide IOC & Ransomware Artifact Scanner

[`poc/scan_darkside_iocs.ps1`](./poc/scan_darkside_iocs.ps1) — A PowerShell script that scans a Windows host for indicators of compromise from the Colonial Pipeline / DarkSide incident using IOCs sourced from CISA Advisory AA21-131A and Malware Analysis Report AR21-189A. Checks for known DarkSide file hashes in common staging directories, searches for ransom note artifacts (`README.*.TXT`), verifies Volume Shadow Copy status (absence may indicate VSS deletion), checks for known DarkSide C2 domain references in the Windows DNS resolver cache and hosts file, and audits Windows Event Log for vssadmin.exe execution (shadow copy deletion) and Rclone/7-Zip execution in unexpected contexts. Produces a color-coded summary with issue counts and immediate response guidance.

### PoC 3: Ransomware Readiness Self-Assessment

[`poc/ransomware_readiness.py`](./poc/ransomware_readiness.py) — A Python script that simulates a ransomware readiness assessment by checking an organization's defensive posture against the specific control failures that enabled the Colonial Pipeline attack. Evaluates five control domains: remote access MFA coverage, account lifecycle management, network egress monitoring, backup and recovery capability, and IT/OT network segmentation. Uses a questionnaire-driven approach (all inputs are manual — no system calls made) and produces a scored readiness report mapped to the NIST Cybersecurity Framework and the specific CISA recommendations from AA21-131A. Demonstrates what a structured pre-incident assessment would look like. Requires Python 3.6+ standard library only.

---

## Remediation

### Immediate Steps

1. **Enforce MFA on all remote access systems — VPN, RDP, Citrix, and any other remote entry point — without exception.**

   ```powershell
   # Audit current MFA enrollment status across all remote access accounts
   # (Azure AD / Entra ID example)
   Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All"
   Get-MgUser -All | ForEach-Object {
       $methods = Get-MgUserAuthenticationMethod -UserId $_.Id
       [PSCustomObject]@{
           User         = $_.UserPrincipalName
           MFA_Methods  = ($methods | Where-Object {
               $_.AdditionalProperties['@odata.type'] -notmatch "passwordAuthentication"
           }).Count
           MFA_Enrolled = ($methods.Count -gt 1)
       }
   } | Where-Object { -not $_.MFA_Enrolled } | Format-Table
   ```

   | Control | Required state |
   |---------|---------------|
   | VPN authentication | MFA required — no exceptions |
   | RDP / remote desktop | MFA required or network-level auth with MFA |
   | Web-based remote access | MFA required |
   | Service accounts with remote access | Certificate-based auth or PAM-vaulted credentials |

2. **Audit and deprovision all inactive remote access accounts.** Any account that has not authenticated in 90 days should have remote access group membership suspended pending review. Accounts belonging to departed employees must be disabled immediately.

3. **Check all credentials against known breach datasets.** Services such as Have I Been Pwned's enterprise API or your identity provider's credential protection features can identify passwords that appear in known breach dumps. Force password resets for any account whose credentials appear in breach data.

4. **Review network egress monitoring coverage.** Identify whether your SIEM or DLP solution would have detected 100 GB of outbound data transfer in a two-hour window. If not, implement data volume thresholds on outbound traffic as a detection control.

5. **Verify backup integrity and test recovery time.** Confirm that backups exist, are stored offline or in an immutable location, and that recovery procedures have been tested recently enough to give confidence in recovery time objectives.

### Short-Term Mitigations (if MFA deployment cannot be completed immediately)

> ⚠️ **These are risk reduction measures only — not substitutes for MFA.**

- **Restrict VPN access by IP allowlist**: limit remote access authentication to known IP ranges (office networks, corporate device IPs). Reduces the pool of locations from which a stolen credential can be used.
- **Disable or restrict legacy VPN profiles**: audit all VPN accounts and disable any not associated with an active, named employee with a documented business need.
- **Enable login anomaly alerting**: alert on any authentication to VPN or remote access systems from IP addresses not previously associated with that account.

### Long-Term Hardening

- **Adopt Zero Trust network architecture for remote access.** VPN grants broad network-layer access once authenticated. Zero Trust models grant access to specific applications and resources only, reducing the blast radius of any credential compromise. CISA's Zero Trust Maturity Model provides a structured roadmap.

- **Implement privileged access management (PAM) for all administrative and service accounts.** PAM vaults credentials, enforces session recording, and ensures service accounts use rotating credentials rather than static passwords that can appear in breach dumps.

- **Treat IT/OT network dependency as a risk to document and mitigate.** Colonial's pipeline shut down because its IT systems were encrypted — not because OT systems were compromised. Identify which OT operations can continue safely without IT systems and document manual operating procedures. CISA's guidance on OT security recommends that critical OT operations have manual fallback capability.

- **Deploy a SIEM with alerting on data exfiltration volume thresholds.** 100 GB leaving the network in two hours is detectable. Set volume-based egress alerts with low thresholds and investigate all alerts — this single control could have detected the Colonial exfiltration before ransomware was deployed.

- **Conduct tabletop exercises specifically for ransomware against IT with OT dependency.** The decision to shut down the pipeline was made under crisis conditions with incomplete information. Tabletop exercises that rehearse this exact scenario — IT encrypted, OT intact, decision: operate or shut down? — produce better-informed decisions during real incidents and reduce the pressure to pay ransom.

---

## Systemic Lessons

**1. A single legacy credential without MFA is sufficient initial access for a devastating critical infrastructure attack.**

The Colonial Pipeline attack required no zero-day exploit, no phishing success, and no sophisticated technical capability for initial access. A username and password from a breach dump opened the door to 5,500 miles of pipeline. Every organization with remote access infrastructure that does not enforce MFA across all accounts has the same exposure. The lesson is not to patch a CVE but to eliminate the class of risk entirely: MFA on all remote access, no exceptions, with active deprovisioning of unused accounts.

**2. Ransomware against IT infrastructure can force shutdown of OT operations without ever touching OT systems.**

Security programs for critical infrastructure have historically focused on protecting OT/ICS systems from direct attack. Colonial demonstrates that this framing is insufficient. An IT-only ransomware attack — one that never crossed the IT/OT boundary — was sufficient to shut down pipeline operations for six days. Resilience planning must account for the dependency of OT operations on IT systems, and critical infrastructure operators must develop and test manual operating procedures that allow OT to continue functioning when IT systems are unavailable.

**3. Double extortion means paying the ransom does not resolve the incident.**

Colonial paid $4.4 million and received a decryption tool that was too slow to be the primary recovery mechanism. More importantly, paying the ransom does not address the 100 GB of stolen data — it remains with the attacker indefinitely, available for future leverage, sale, or publication. Organizations need to design their incident response and ransom payment decisions around the reality that data exfiltration has already succeeded by the time ransomware fires. The question is not only "can we decrypt our files?" but "what data was taken and what are the consequences of its publication?"

**4. Egress monitoring is as critical as ingress monitoring, and most organizations underinvest in it.**

The 100 GB exfiltration that created DarkSide's leverage in the Colonial attack occurred before the ransomware was deployed. Detecting and stopping the exfiltration would have preserved the attacker's leverage even if the ransomware subsequently ran. Most security programs invest heavily in blocking inbound attacks and relatively little in monitoring outbound data movement. A DLP or SIEM rule alerting on anomalous egress volume would have been the earliest possible detection point in this intrusion.

**5. The RaaS model decouples technical sophistication from operational impact, and defenders must account for this.**

The DarkSide affiliate who attacked Colonial Pipeline did not need to develop ransomware, build a data leak site, manage cryptocurrency infrastructure, or negotiate with victims. GOLD WATERFALL provided all of that as a service. The affiliate's primary skill requirement was gaining initial access and deploying a tool — a task that was accomplished with a stolen credential. The implication is that the barrier to conducting a devastating ransomware attack against critical infrastructure is much lower than the operational outcome suggests. Security programs that focus on defending against sophisticated adversaries need to also address elementary access control failures.

---

## References

See [references.md](./references.md) for the full annotated source list.

**Primary sources:**
- [CISA / FBI — Joint Advisory AA21-131A: DarkSide Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a) (authoritative technical advisory; IOCs; MITRE ATT&CK mapping)
- [CISA — Malware Analysis Report AR21-189A: DarkSide Ransomware](https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-189a) (DarkSide binary analysis and file hashes)
- [Secureworks — GOLD WATERFALL Threat Profile](https://www.secureworks.com/research/threat-profiles/gold-waterfall) (attribution; RaaS model; affiliate structure)
- [Senate Commerce Committee — Testimony of Joseph Blount, CEO Colonial Pipeline (June 8, 2021)](https://www.commerce.senate.gov/2021/6/examining-threats-to-america-s-critical-infrastructure) (MFA absence; ransom payment decision; timeline)
- [US DOJ — Press Release: DOJ Recovers Majority of Colonial Pipeline Ransom (June 7, 2021)](https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside) (ransom recovery; Bitcoin seizure)
- [CISA — Two Years After Colonial Pipeline: What We've Learned](https://www.cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years) (post-incident policy and defensive improvements)
- [Trend Micro — What We Know About DarkSide and the US Pipeline Attack](https://www.trendmicro.com/en_us/research/21/e/what-we-know-about-darkside-ransomware-and-the-us-pipeline-attac.html) (technical TTPs; exfiltration tooling)
- [MITRE ATT&CK — G0139: DarkSide Group](https://attack.mitre.org/groups/G0139/) (ATT&CK technique mapping for DarkSide campaigns)

---

*Analysis compiled from public threat intelligence. Last updated: June 2026.*
