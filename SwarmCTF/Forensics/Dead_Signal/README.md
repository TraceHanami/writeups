# Operation: Dead Signal — Forensic Incident Response Writeup

## Metadata
- **Challenge Name:** Operation: Dead Signal
- **CTF / Event:** SwarmCTF 2026
- **Category:** Forensics / Incident Response / Signal Analysis / Cryptography
- **Difficulty:** Hard
- **Artifacts:**
  - Archive: `dead_signal.zip`
  - Briefing: `README.txt`
  - Hashes: `manifest.sha256`
  - Forensic Evidence:
    - `station_traffic.log` (Gateway network traffic)
    - `telemetry.raw` (Carved flash memory telemetry)
    - `sensor_feed.dat` (Acoustic / VLF hydrophone audio recording)
    - `system_diag.log` (Subsystem & kernel diagnostics)
    - `core_dump.raw` (Physical memory dump during brownout)
  - Recovery Scripts & Results:
    - [`recover_flag.py`](solve.py)
    - `recovery_report.txt`
    - `vault_decrypted.json`
- **Status:** Solved & Verified
- **Flag:** `swarm{0rph3u5_5ub5urf4c3_51gn4l_r3c0n57ruc73d_7a9f}`

---

## Challenge Overview
At 03:17 UTC on 2026-10-20, Sub-Antarctic Marine & Atmospheric Research Facility ORPHEUS abruptly severed all communications following an unprompted catastrophic failure. An emergency surface reconnaissance vessel recovered five raw artifacts from the hardened Emergency Storage Unit (ESU).

The challenge requires cross-referencing timestamps, hardware authentication tags, network streams, acoustic hydrophone signals, and physical memory structures to recover four cryptographic keys ($K_1, K_2, K_3, K_4$) and decrypt the station's encrypted blackbox telemetry vault.

---

## Forensic Analysis & Key Recovery

### 1. Network Traffic Reassembly ($K_1$)
- **Artifact:** `station_traffic.log`
- **Protocol:** Custom `ORPHPKT` UDP packet stream.
- **Analysis:**
  Parsing UDP packets matching header signature `ORPHPKT` identifies out-of-order sequence fragments. Reassembling valid sequence numbers while discarding corrupted and spoofed packets extracts the genuine broadcast segment:
- **Recovered Component $K_1$:**
  `d9f82a6c1e3b5e40a719284c56e07b8a`

### 2. Carved Flash Archive Telemetry ($K_2$)
- **Artifact:** `telemetry.raw`
- **Analysis:**
  The binary contains variable-length telemetry frames. Cross-referencing station sensor IDs and CRC validation checks locates an authenticated record header at byte offset `0x0C85`. Decrypting this record with the station session key yields:
- **Recovered Component $K_2$:**
  `7a41c30e2f9d86b51048e762c93d14f0`

### 3. VLF Hydrophone Signal Demodulation ($K_3$)
- **Artifact:** `sensor_feed.dat`
- **Modulation Scheme:** 2-FSK acoustic hydrophone transmission (mark frequency: 1200 Hz, space frequency: 2200 Hz).
- **Analysis:**
  Passing the raw acoustic hydrophone recording through a bandpass filter and demodulating the audio via zero-crossing interval estimation reconstructs the bitstream. Parsing framing bytes and validating CRC-16 integrity recovers:
- **Recovered Component $K_3$:**
  `8c6b90e1f42a537d45e0321876ab129f`

### 4. Memory Core Dump Carving ($K_4$)
- **Artifact:** `core_dump.raw`
- **Analysis:**
  Scanning the 256 KB memory fragment reveals kernel execution state at the time of brownout. Locating the active `EMERGENCY_SEAL` session block at offset `0x22100` yields the fourth component:
- **Recovered Component $K_4$:**
  `e3c8d15a720964bf85210ce84b39a2f1`

---

## Vault Decryption & Flag Recovery

### Master Key Derivation
The four components are joined with colons and hashed using SHA-256:
$$\text{Preimage} = K_1 : K_2 : K_3 : K_4$$
$$\text{Master Key} = \text{SHA-256}(K_1 : K_2 : K_3 : K_4)$$
- **Master Key:** `26a8cc2c8c78d2a1d18c1b6f736f9df13452b13023139b7e03a9aad3fe6f8007`

### Vault Decryption
Carving from `core_dump.raw` at offset `0x31000` reveals an encrypted AES-CBC vault payload:
- **IV:** `2d23d4c371b76cd11510f2b4bb2c067d`
- **Ciphertext Length:** 400 bytes

Decryption via AES-256-CBC yields `vault_decrypted.json`:
```json
{
  "station": "ORPHEUS-STN-07",
  "incident_id": "ORPH-2026-10-20-0317",
  "status": "ALL_CHANNELS_SILENT",
  "coordinates": "LAT -71.1824 | LON -012.3481",
  "timestamp_utc": 1792466218,
  "blackbox_dispatch": "Station ORPHEUS core power lost. Automatic emergency beacon deployed. Signal reconstructed successfully.",
  "flag": "swarm{0rph3u5_5ub5urf4c3_51gn4l_r3c0n57ruc73d_7a9f}"
}
```

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Solver Script | [`recover_flag.py`](solve.py) | Complete Python automation orchestrating multi-channel signal recovery |
| Report | `recovery_report.txt` | Detailed technical breakdown of all 4 key derivations |
| Decrypted Vault | `vault_decrypted.json` | Decrypted blackbox JSON containing the recovered flag |
