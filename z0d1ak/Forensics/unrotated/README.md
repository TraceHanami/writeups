# Unrotated — CTF Challenge Writeup

**Category:** Digital Forensics / Incident Response  
**Challenge:** Unrotated (`forensics_unrotated`)  
**Event:** z0d1ak CTF  
**Flag:** `zdk{a_humaN_rEAD5_tHE_WakE_nOt_th3_laBe15}`

---

## 1. Challenge Overview

We are provided with an incident triage archive (`forensics_unrotated.zip` containing `unrotated-evidence.zip`) simulating an intrusion across an enterprise collaboration and worker infrastructure called **Pelagos**. 

The evidence collection includes 15 artifacts across identity, governance, collaboration, network, and host layers:
- `identity/rotation_manifest.csv` & `identity/partner_registry.csv`
- `governance/change_ledger.csv`
- `collaboration/audit.csv` & `collaboration/directory.db` (SQLite)
- `gateway/access.log`
- `repository/access.csv`
- `network/firewall.csv`, `network/approved_egress.csv`, & `network/host_inventory.csv`
- `host/system.journal` (systemd journal), `host/watch-console.cast` (asciicast recording), `host/route-patch-panel.png`, `host/runner-cache.oci.tar` (OCI image cache), & `host/relay_socket_legend.csv`

Connecting to the remote interactive challenge service at `ncat --ssl unrotated-b1feee39a64d.chals.z0d1ak.org 1337` asks seven specific investigation questions to reconstruct the entire attack chain.

---

## 2. Step-by-Step Investigation & Artifact Analysis

### [1] Initial Access Credential
Examining `identity/rotation_manifest.csv` for batch `ROT-2026-061` on `2026-06-09T06:00:00Z`:
```csv
batch_id,token_uuid,label,fingerprint,principal_uuid,scheduled_utc,completed_utc,review_note
ROT-2026-061,947c3053-eb19-44a4-a8bb-50e2ed97886c,depth-chart-archive,af6717eb72a9c4eeb79b,78ea4f91-86c4-437b-8738-d6f210f8d8bb,2026-06-09T06:00:00Z,,owner reported connector retired
```
Although the service principal `78ea4f91-86c4-437b-8738-d6f210f8d8bb` (`svc-depth-archive`) was marked disabled (`enabled=0`) in `collaboration/directory.db`, the API token `depth-chart-archive` (fingerprint `af6717eb72a9c4eeb79b`) was skipped during rotation and remained active.

* **Answer:** `depth-chart-archive`

---

### [2] First Confirmed Intrusion Session
Filtering `collaboration/audit.csv` and `gateway/access.log` for the compromised token/principal:
```csv
2026-06-11T09:26:41Z,evt-e906e207cc3bcccd,req-5092a3f3bf6dfca2,78ea4f91-86c4-437b-8738-d6f210f8d8bb,session_start,gateway,success,integration token accepted
```
The attacker established their first authenticated session from external IP `198.51.100.73` at this exact timestamp before performing wiki reconnaissance on `remote access` and `integration owner`.

* **Answer:** `2026-06-11T09:26:41Z`

---

### [3] Persistence Identity
Inspecting `collaboration/audit.csv` and querying `collaboration/directory.db`:
```csv
2026-06-12T14:08:11Z,evt-0762201e8b8ebd6c,req-e8d7b5b09bf6c967,78ea4f91-86c4-437b-8738-d6f210f8d8bb,principal_create,principal/aa839c52-32ac-4d89-af86-76e53f6f3898,success,account type=human change_ref=CHG-2147
2026-06-12T14:10:02Z,evt-759a2f6d84ff9c52,req-ee322f7b13a64f7a,78ea4f91-86c4-437b-8738-d6f210f8d8bb,group_member_add,platform-admins/aa839c52-32ac-4d89-af86-76e53f6f3898,success,membership granted change_ref=CHG-2147
```
In `directory.db`, principal UUID `aa839c52-32ac-4d89-af86-76e53f6f3898` corresponds to account name `mara.venn`.

* **Answer:** `mara.venn`

---

### [4] Misappropriated Legitimate Change Record
In `governance/change_ledger.csv`:
```csv
CHG-2147,2026-06-12T13:30:00Z,2026-06-12T14:30:00Z,5418adbe-06df-4561-bf33-36b98580b16e,group_member_add,f5ec1e2e-b76c-4974-859c-4ae8e44ca245,approved,Promote on-call platform engineer after access review
```
Change record `CHG-2147` was legitimately approved for promoting `nora.alves` (`f5ec1e2e-b76c-4974-859c-4ae8e44ca245`). The attacker fraudulently referenced `CHG-2147` as cover to create `mara.venn` and add her to `platform-admins`.

* **Answer:** `CHG-2147`

---

### [5] Delegated Host Compromise Runner Job
Inspecting `collaboration/audit.csv` and `gateway/access.log` for requests by `mara.venn` on `2026-06-18`:
```csv
2026-06-18T03:44:52Z,evt-70580c643bc4cf8a,req-e21c3a41be04c6f6,aa839c52-32ac-4d89-af86-76e53f6f3898,runner_job_submit,opsrunner/jobs/OR-7312,accepted,execution delegated to collab-app-01 change_ref=CHG-2147
```
In `host/system.journal`, job `OR-7312` spawned worker child process `PID 24144` (`pool_slot=ae6cb163`, `component=plugin-cache`).

* **Answer:** `OR-7312`

---

### [6] Operation Name and External Rendezvous (`operation@endpoint:port`)
1. **External Rendezvous:**
   Correlating `network/firewall.csv` at `2026-06-18T03:46:03Z` (during `OR-7312`):
   ```csv
   2026-06-18T03:46:03Z,fl-be2e19a16c84c516,10.42.7.19,203.0.113.86,8448,tcp,allow,jvm-agent,proc-7ae13f0c35d8,legacy-general-egress
   ```
   Destination `203.0.113.86:8448` is not present in `network/approved_egress.csv`.

2. **Operation Name Mapping:**
   - In `host/runner-cache.oci.tar`, `cache-f` was compiled on `2026-06-12` (the date of `CHG-2147` and `mara.venn` creation) with profile `survey` and screen ref `watch-64a7a9d8bbd9`.
   - Decoding the ANSI terminal stream in `host/watch-console.cast`:
     `watch-64a7a9d8bbd9` is routed via `LEAD-E`.
   - Tracing `LEAD-E` across `host/route-patch-panel.png` connects to `SOCKET-6`.
   - In `host/relay_socket_legend.csv`, `SOCKET-6` maps to operation **`BLUEFIN`**.

* **Answer:** `BLUEFIN@203.0.113.86:8448`

---

### [7] Follow-On Non-Production Target Hostname
In `network/firewall.csv` at `2026-06-18T03:51:28Z` (shortly after the unauthorized egress):
```csv
2026-06-18T03:51:28Z,fl-...,10.42.7.19,10.43.18.61,22,tcp,deny,jvm-agent,proc-7ae13f0c35d8,segmentation-default-deny
```
Looking up IP `10.43.18.61` in `network/host_inventory.csv`:
```csv
hostname,address,environment,owner
console-cpt-03,10.43.18.61,non-production,network-lab
```

* **Answer:** `console-cpt-03`

---

## 3. Incident Summary Matrix

| Question | Forensic Answer | Evidence Pointer |
| :--- | :--- | :--- |
| **[1] Initial Access Credential** | `depth-chart-archive` | `identity/rotation_manifest.csv` |
| **[2] First Authentication Time** | `2026-06-11T09:26:41Z` | `collaboration/audit.csv` (`evt-e906e207cc3bcccd`) |
| **[3] Persistence Identity** | `mara.venn` | `collaboration/directory.db` (`aa839c52-32ac-4d89-af86-76e53f6f3898`) |
| **[4] Reused Change Record** | `CHG-2147` | `governance/change_ledger.csv` |
| **[5] Delegated Runner Job** | `OR-7312` | `collaboration/audit.csv` & `host/system.journal` |
| **[6] Operation & Rendezvous** | `BLUEFIN@203.0.113.86:8448` | `host/route-patch-panel.png` + `network/firewall.csv` |
| **[7] Follow-on Target Hostname** | `console-cpt-03` | `network/firewall.csv` + `network/host_inventory.csv` |

---

## 4. Exploitation / Solution Script

```python
#!/usr/bin/env python3
import socket
import ssl

HOST = "unrotated-b1feee39a64d.chals.z0d1ak.org"
PORT = 1337

ANSWERS = [
    "depth-chart-archive",
    "2026-06-11T09:26:41Z",
    "mara.venn",
    "CHG-2147",
    "OR-7312",
    "BLUEFIN@203.0.113.86:8448",
    "console-cpt-03",
]

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
            # Consume banner
            buf = ""
            while "report[1]>" not in buf:
                buf += ss.recv(4096).decode()
            print(buf, end="")

            for i, ans in enumerate(ANSWERS, 1):
                print(ans)
                ss.sendall((ans + "\n").encode())
                buf = ""
                while True:
                    chunk = ss.recv(4096).decode()
                    buf += chunk
                    if f"report[{i+1}]>" in buf or "flag" in buf.lower() or not chunk:
                        break
                print(buf, end="")

if __name__ == "__main__":
    main()
```

### Output & Flag Verification
```text
report[1]> depth-chart-archive
report[2]> 2026-06-11T09:26:41Z
report[3]> mara.venn
report[4]> CHG-2147
report[5]> OR-7312
report[6]> BLUEFIN@203.0.113.86:8448
report[7]> console-cpt-03
Investigation complete.
Flag: zdk{a_humaN_rEAD5_tHE_WakE_nOt_th3_laBe15}
```
