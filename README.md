# 🔍 Vulnerability Research

A curated collection of in-depth vulnerability writeups covering real-world security incidents in the software ecosystem. Each entry includes a full technical analysis, proof-of-concept, IOC listing, and remediation guidance.

> **Purpose:** Educational reference and portfolio. All PoC code is for detection and research only.

---

## Index

| # | Vulnerability | Type | Severity | Date | Status |
|---|---------------|------|----------|------|--------|
| 006 | [Colonial Pipeline — DarkSide Ransomware Incident](./../../../colonial-pipeline-darkside-cyberattack/) | Ransomware | 🔴 Critical | May 6, 2021 | ✅ Complete |

---

## Structure

Each entry follows a consistent format:

```
colonial-pipeline-darkside-cyberattack/
├── README.md                        # Project overview
├── analysis.md                      # Full writeup
├── references.md                    # Cited sources
└── poc/                             # Detection & PoC scripts
    │ 
    ├── audit_remote_access.ps1          # PoC 1: AD account exposure auditor
    ├── scan_darkside_iocs.ps1           # PoC 2: DarkSide IOC scanner (CISA hashes)
    └── ransomware_readiness.py          # PoC 3: readiness self-assessment
```

## Methodology

The writeup covers:
- **Root cause** — what actually broke and how 
- **Attack timeline** — pre-staging, execution, discovery, remediation
- **Technical deep-dive** — deobfuscated payloads, attack chain, IOCs
- **PoC** — reproduction or detection scripts
- **Lessons learned** — systemic issues and mitigations

---

*Maintained by [@horrister](https://github.com/horrister)*
