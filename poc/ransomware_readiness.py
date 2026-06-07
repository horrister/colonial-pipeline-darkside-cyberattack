#!/usr/bin/env python3
"""
ransomware_readiness.py
Colonial Pipeline / DarkSide Ransomware Incident — 2021
Ransomware Readiness Self-Assessment

A questionnaire-driven assessment that evaluates an organization's
defensive posture against the specific control failures that enabled
the Colonial Pipeline attack.

Evaluates five control domains drawn from CISA Advisory AA21-131A
and the CISA #StopRansomware Guide:
  1. Remote access MFA coverage
  2. Account lifecycle management
  3. Network egress monitoring
  4. Backup and recovery capability
  5. IT/OT network segmentation

Produces a scored readiness report mapped to NIST CSF functions
and specific CISA recommendations.

SAFETY: This script makes ZERO system calls. All inputs are manual
        (typed responses to questions). No files are read or written.
        No network connections are made.

Run:
    python3 ransomware_readiness.py

Requirements: Python 3.6+ standard library only.
"""

import sys

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

# ── Scoring constants ──────────────────────────────────────────────────────────

SCORE_YES     = 2   # Control fully implemented
SCORE_PARTIAL = 1   # Control partially implemented
SCORE_NO      = 0   # Control absent

# ── NIST CSF mapping ───────────────────────────────────────────────────────────

CSF_MAP = {
    "mfa":        "PR.AC-7  (Protect: Access Control)",
    "accounts":   "PR.AC-1  (Protect: Identities and credentials managed)",
    "egress":     "DE.CM-1  (Detect: Network monitored for anomalous events)",
    "backup":     "RC.RP-1  (Recover: Recovery plan executed)",
    "segmentation": "PR.AC-5 (Protect: Network integrity protected)",
}

# ── Question definitions ────────────────────────────────────────────────────────
# Each domain: list of (question_text, weight, cisa_recommendation)
# Weight 2 = critical control (directly maps to Colonial failure)
# Weight 1 = important control (reduces blast radius)

DOMAINS = {
    "mfa": {
        "label": "Remote Access MFA Coverage",
        "colonial_failure": "VPN account with no MFA was the sole initial access vector",
        "questions": [
            ("Is MFA enforced on ALL VPN accounts — including legacy/inactive accounts?",
             2, "CISA AA21-131A: Implement MFA on all remote access"),
            ("Is MFA enforced on all Remote Desktop Protocol (RDP) access?",
             2, "CISA AA21-131A: Require MFA for remote desktop services"),
            ("Is MFA enforced on all web-based remote access portals (Citrix, VDI)?",
             1, "CISA #StopRansomware: MFA on all internet-facing remote access"),
            ("Are service accounts with remote access using certificate auth or PAM-vaulted credentials?",
             1, "CISA AA21-131A: Enforce strong auth on service accounts"),
        ]
    },
    "accounts": {
        "label": "Account Lifecycle Management",
        "colonial_failure": "Compromised account was inactive but not deprovisioned",
        "questions": [
            ("Is there a documented process to disable remote access for departed employees within 24 hours?",
             2, "CISA AA21-131A: Implement account deprovisioning procedures"),
            ("Are remote access group memberships audited quarterly or more frequently?",
             2, "CISA AA21-131A: Regularly audit user accounts and access rights"),
            ("Are credentials checked against known breach datasets (e.g. HaveIBeenPwned API)?",
             1, "CISA #StopRansomware: Monitor for compromised credentials"),
            ("Is password reuse across systems prevented by policy and technical enforcement?",
             1, "CISA AA21-131A: Implement strong password policies"),
        ]
    },
    "egress": {
        "label": "Network Egress Monitoring",
        "colonial_failure": "100 GB exfiltrated in ~2 hours without detection",
        "questions": [
            ("Does your SIEM alert on anomalous outbound data volume (e.g. >10 GB in 1 hour)?",
             2, "CISA AA21-131A: Monitor and filter network traffic"),
            ("Is DLP deployed to detect and alert on bulk file transfers to cloud storage?",
             1, "CISA #StopRansomware: Implement data loss prevention"),
            ("Are egress firewall rules in place restricting outbound access to approved destinations?",
             2, "CISA AA21-131A: Implement egress filtering"),
            ("Are proxy logs reviewed for connections to cloud sync services (Mega, Rclone patterns)?",
             1, "CISA AA21-131A: Monitor for exfiltration tool usage"),
        ]
    },
    "backup": {
        "label": "Backup and Recovery Capability",
        "colonial_failure": "Decryptor provided by attacker was slower than backup recovery",
        "questions": [
            ("Are backups stored in an immutable or offline location inaccessible to ransomware?",
             2, "CISA #StopRansomware: Maintain offline, encrypted backups"),
            ("Has recovery from backup been tested within the last 6 months?",
             2, "CISA #StopRansomware: Test backup restoration procedures"),
            ("Are recovery time objectives (RTOs) documented and validated through testing?",
             1, "CISA #StopRansomware: Define and test recovery objectives"),
            ("Are Volume Shadow Copies enabled and protected from deletion by non-admin accounts?",
             1, "CISA AA21-131A: Protect backup mechanisms from tampering"),
        ]
    },
    "segmentation": {
        "label": "IT/OT Network Segmentation",
        "colonial_failure": "IT compromise forced OT shutdown despite OT network not being breached",
        "questions": [
            ("Are IT and OT networks segmented with documented, enforced access controls?",
             2, "CISA AA21-131A: Segment OT networks from IT networks"),
            ("Can OT operations continue safely if IT systems are unavailable?",
             2, "CISA ICS-CERT: Document manual operating procedures for OT"),
            ("Are OT-to-IT connections logged and anomalous traffic alerted on?",
             1, "CISA AA21-131A: Monitor cross-boundary traffic"),
            ("Is there a documented decision tree for 'operate vs shut down' when IT is compromised?",
             1, "INL Colonial Case Study: Pre-plan OT continuity decisions"),
        ]
    }
}

MAX_SCORE_PER_DOMAIN = sum(q[1] * SCORE_YES for q in list(DOMAINS.values())[0]["questions"])


# ── Input helper ───────────────────────────────────────────────────────────────

def ask(question: str, weight: int) -> int:
    """Ask a yes/partial/no question and return the weighted score."""
    print(f"\n  {CYAN}Q:{RESET} {question}")
    print(f"     {GRAY}[y] Yes — fully implemented  "
          f"[p] Partial — in progress  [n] No — not implemented{RESET}")

    while True:
        try:
            answer = input("     Your answer: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Assessment interrupted.")
            sys.exit(0)

        if answer in ("y", "yes"):
            return weight * SCORE_YES
        elif answer in ("p", "partial"):
            return weight * SCORE_PARTIAL
        elif answer in ("n", "no"):
            return weight * SCORE_NO
        else:
            print("     Please enter y, p, or n")


# ── Scoring helpers ────────────────────────────────────────────────────────────

def score_to_label(score: int, max_score: int) -> str:
    pct = score / max_score if max_score > 0 else 0
    if pct >= 0.85:
        return f"{GREEN}Strong{RESET}"
    elif pct >= 0.60:
        return f"{YELLOW}Moderate{RESET}"
    else:
        return f"{RED}Weak — immediate attention required{RESET}"


def score_to_bar(score: int, max_score: int, width: int = 30) -> str:
    pct = score / max_score if max_score > 0 else 0
    filled = int(pct * width)
    color = GREEN if pct >= 0.85 else (YELLOW if pct >= 0.60 else RED)
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{RESET} {score}/{max_score}"


# ── Main assessment ────────────────────────────────────────────────────────────

def run_assessment():
    print(f"""
{BOLD}{'=' * 64}{RESET}
 Ransomware Readiness Self-Assessment
 Based on: Colonial Pipeline / DarkSide Incident, May 2021
 Reference: CISA Advisory AA21-131A + CISA #StopRansomware Guide
 SAFE: No system calls. All responses are manual input only.
{'=' * 64}{RESET}

 This assessment evaluates your organization's defensive posture
 against the five control domains that determined the outcome of
 the Colonial Pipeline ransomware attack.

 Answer each question: y (yes), p (partial), or n (no)
 The assessment takes approximately 5-10 minutes.
""")

    input(f" Press Enter to begin... ")

    domain_scores   = {}
    domain_maximums = {}
    all_gaps        = []

    for domain_key, domain_data in DOMAINS.items():
        print(f"\n{BOLD}{'─' * 64}{RESET}")
        print(f"{BOLD}Domain: {domain_data['label']}{RESET}")
        print(f"{GRAY}Colonial failure: {domain_data['colonial_failure']}{RESET}")
        print(f"{GRAY}NIST CSF: {CSF_MAP[domain_key]}{RESET}")

        domain_score = 0
        domain_max   = 0

        for question, weight, recommendation in domain_data["questions"]:
            score = ask(question, weight)
            domain_score += score
            domain_max   += weight * SCORE_YES

            if score < weight * SCORE_YES:
                all_gaps.append({
                    "domain":         domain_data["label"],
                    "question":       question,
                    "score":          score,
                    "max":            weight * SCORE_YES,
                    "recommendation": recommendation,
                    "critical":       weight == 2,
                })

        domain_scores[domain_key]   = domain_score
        domain_maximums[domain_key] = domain_max

    return domain_scores, domain_maximums, all_gaps


# ── Report output ──────────────────────────────────────────────────────────────

def print_report(domain_scores: dict, domain_maximums: dict, all_gaps: list):
    total_score = sum(domain_scores.values())
    total_max   = sum(domain_maximums.values())
    overall_pct = total_score / total_max if total_max > 0 else 0

    print(f"\n\n{BOLD}{'=' * 64}{RESET}")
    print(f"{BOLD} RANSOMWARE READINESS ASSESSMENT REPORT{RESET}")
    print(f"{BOLD} Colonial Pipeline / DarkSide Incident — CISA AA21-131A{RESET}")
    print(f"{'─' * 64}")

    # Overall score
    overall_label = score_to_label(total_score, total_max)
    print(f"\n {BOLD}Overall readiness: {overall_label}{RESET}")
    print(f" {score_to_bar(total_score, total_max)}")
    print(f" {int(overall_pct * 100)}% of controls implemented")

    # Domain breakdown
    print(f"\n {BOLD}Domain scores:{RESET}")
    print(f" {'─' * 56}")

    for domain_key, domain_data in DOMAINS.items():
        score = domain_scores[domain_key]
        max_s = domain_maximums[domain_key]
        label = score_to_label(score, max_s)
        bar   = score_to_bar(score, max_s, width=20)
        print(f"\n  {domain_data['label']}")
        print(f"  {bar}  {label}")
        print(f"  {GRAY}NIST CSF: {CSF_MAP[domain_key]}{RESET}")

    # Gap analysis
    critical_gaps = [g for g in all_gaps if g["critical"] and g["score"] == 0]
    other_gaps    = [g for g in all_gaps if not (g["critical"] and g["score"] == 0)]

    if critical_gaps:
        print(f"\n {BOLD}{'─' * 56}{RESET}")
        print(f" {BOLD}{RED}CRITICAL GAPS — controls absent that directly enabled Colonial Pipeline breach:{RESET}")
        for gap in critical_gaps:
            print(f"\n  {RED}[CRITICAL]{RESET} {gap['domain']}")
            print(f"  Control:  {gap['question'][:70]}...")
            print(f"  Action:   {gap['recommendation']}")

    if other_gaps:
        print(f"\n {BOLD}{'─' * 56}{RESET}")
        print(f" {BOLD}{YELLOW}IMPROVEMENT AREAS — partially or not implemented:{RESET}")
        for gap in other_gaps:
            marker = YELLOW + "[PARTIAL]" + RESET if gap["score"] > 0 else YELLOW + "[ABSENT] " + RESET
            print(f"\n  {marker} {gap['domain']}")
            print(f"  Control:  {gap['question'][:70]}...")
            print(f"  Action:   {gap['recommendation']}")

    # Prioritized next steps
    print(f"\n {BOLD}{'─' * 56}{RESET}")
    print(f" {BOLD}Prioritized remediation — mapped to Colonial Pipeline root causes:{RESET}")
    print(f"""
  1. {BOLD}MFA on all remote access{RESET} — no exceptions, no legacy accounts
     This single control would have prevented the Colonial Pipeline breach.
     Target: 100% coverage within 30 days.
     Reference: CISA AA21-131A Section 3.1

  2. {BOLD}Account deprovisioning audit{RESET} — disable all inactive remote access accounts
     The compromised account was inactive. Audit and disable within 90 days.
     Reference: CISA AA21-131A Section 3.2

  3. {BOLD}Egress volume alerting{RESET} — alert on >10 GB outbound per hour
     100 GB exfiltrated in ~2 hours before ransomware fired. This is detectable.
     Reference: CISA #StopRansomware Guide, Section 4

  4. {BOLD}Offline/immutable backup testing{RESET} — test restore within 6 months
     Colonial's backups existed but recovery was slower than expected.
     Reference: CISA #StopRansomware Guide, Section 5

  5. {BOLD}OT continuity planning{RESET} — document manual operating procedures
     Pipeline shut down because IT failure made OT operation unsafe to confirm.
     Reference: CISA ICS Advisory, INL Colonial Case Study
""")

    print(f" {BOLD}References:{RESET}")
    print(f"  CISA AA21-131A:         https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a")
    print(f"  CISA #StopRansomware:   https://www.cisa.gov/resources-tools/resources/stopransomware-guide")
    print(f"  NIST CSF:               https://www.nist.gov/cyberframework")
    print(f"\n{'=' * 64}\n")


def main():
    try:
        domain_scores, domain_maximums, all_gaps = run_assessment()
        print_report(domain_scores, domain_maximums, all_gaps)
    except KeyboardInterrupt:
        print(f"\n\n  Assessment cancelled.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
