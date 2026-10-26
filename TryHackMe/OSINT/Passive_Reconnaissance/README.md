# TryHackMe — Passive Reconnaissance (Room Completion Report)

**Platform:** TryHackMe  
**Room Name:** Passive Reconnaissance  
**Completion Date:** October 2, 2026 at 22:20:24 UTC  
**Artifacts:**
- `261002_22h20m24s_screenshot.png` (117,593 bytes 100% completion badge)  
**Status:** Completed (100% Verified)  

---

## 1. Overview & Verification

The primary artifact is `261002_22h20m24s_screenshot.png`, capturing the official TryHackMe room completion badge:
- **Module:** Network Security & Pre-Engagement / Passive Reconnaissance
- **Completion Status:** 100% of tasks completed and submitted
- **Points Awarded:** Maximum room XP credited to user account

---

## 2. Core Methodologies Mastered

### A. WHOIS Registry Enumeration
- Querying WHOIS databases (`whois <domain>`) to identify registrar information, technical contacts, registration creation and expiry dates, and registered name servers.
- Utilizing privacy protection detection and identifying registrar abuse contacts.

### B. DNS Reconnaissance
- Querying Authoritative Name Servers using `nslookup` and `dig`:
  - `dig A <domain>`: Host IPv4 address mapping.
  - `dig MX <domain>`: Mail exchange servers and priority configurations.
  - `dig TXT <domain>`: Domain verification records, SPF (`v=spf1`), and DKIM policies.
  - `dig NS <domain>`: Authoritative nameservers.
- Passive DNS tools and certificate transparency logs (e.g. `crt.sh`) for discovering unindexed subdomains.

### C. Search Engine Dorking (Google Hacking Database)
- Advanced search operators:
  - `site:target.com`: Restrict queries to the target domain.
  - `filetype:pdf | filetype:docx | filetype:xls`: Identify exposed corporate documents.
  - `inurl:admin | inurl:login`: Discover sensitive authentication portals.
  - `intitle:"index of"`: Identify directory listing vulnerabilities.

### D. Specialized OSINT & Archive Reconnaissance
- **Shodan / Censys:** Gathering public port scan data, TLS certificates, service banners, and IoT device fingerprints without directly interacting with target IP space.
- **Wayback Machine (Archive.org):** Inspecting historical snapshots of target web applications to find removed employee lists, deprecated API endpoints, and leaked credentials.
