# CREST CTF 2026 — Worker State Recovery

**Category:** Miscellaneous / Configuration Forensics  
**CTF Event:** CREST CTF 2026  
**Artifacts:**
- `usr_local_bin_rotate_worker_state` (1,162 bytes configuration state file)  
**Status:** Solved  
**Recovered Flag:** `CREST{ServiceRecovered08X}`  

---

## 1. Challenge Overview

The challenge provides a recovered worker service state dump `usr_local_bin_rotate_worker_state` capturing worker rotation counters and checkpoint statistics.

---

## 2. Artifact Inspection & Flag Recovery

Inspecting the configuration file reveals service rotation checkpoints matching the schema `rotate-worker-v2`:
```text
utility_schema=rotate-worker-v2
rotate_stat_00=count:1
rotate_stat_01=count:30
rotate_stat_02=count:59
rotate_stat_03=count:88
rotate_stat_04=count:117
rotate_stat_05=count:146
rotate_stat_06=count:175
rotate_stat_07=count:204
rotate_stat_08=count:233 annotation=CREST{ServiceRecovered08X}
rotate_stat_09=count:262
rotate_stat_10=count:291
...
```

At rotation checkpoint 08 (`rotate_stat_08`), an operational recovery annotation contains the flag:
```text
CREST{ServiceRecovered08X}
```
Validation confirms standard format `CREST{...}`.
