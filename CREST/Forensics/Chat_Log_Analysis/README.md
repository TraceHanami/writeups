# CREST CTF 2026 — Chat Log Analysis (CREST-CHAT/2)

**Category:** Forensics / Log Analysis  
**CTF Event:** CREST CTF 2026  
**Artifacts:**
- `bravo(1).cblog` (97,473,446 bytes JSON audit log)
- `bravo.cblog` (0 bytes empty download marker)
- `bravo.m4iDP16w.cblog.part` (48,614,456 bytes partial download)  
**Status:** In-Progress / Log Forensic Investigation  

---

## 1. Challenge Overview

The challenge presents a large 97MB structured transaction log `bravo(1).cblog` documenting interactions and events across internal microservices (`auth-proxy-01`, `health-agent-02`, `auditd-03`, `replica-sync-04`, `retentiond-06`). The log begins with protocol banner:
```text
CREST-CHAT/2
```

---

## 2. Log Structure & Anomaly Hunting

Each log entry is serialized as a JSON object:
```json
{
  "ts": "2026-10-01T00:00:00.000Z",
  "host": "auth-proxy-01",
  "level": "NOTICE",
  "event": "temporary upstream delay observed",
  "msg": "retry scheduled with b",
  "rid": "cced8bbb84a7a4",
  "latency_ms": 774,
  "status": 200
}
```

### Analysis Vectors:
1. **Request ID (`rid`) Steganography:** Testing whether hexadecimal request IDs conceal encoded ASCII bytes or binary sequences.
2. **Timing Anomalies & Latency Spikes:** Filtering entries where `latency_ms` deviates significantly or conveys covert timing channels.
3. **HTTP Status Code Sequences:** Extracting events with status codes 429, 502, or custom return codes.
4. **Message Suffix Reconstruction:** Several `msg` fields end prematurely (`"msg":"retry scheduled with b"`, `"msg":"read replica acknowled"`). Concatenating truncated message fragments reveals the hidden transmission payload.
