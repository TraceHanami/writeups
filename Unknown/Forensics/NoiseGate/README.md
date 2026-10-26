# NoiseGate — Bluetooth Low Energy (BLE) Forensics & Protocol Cryptanalysis

**Category:** IoT Security / Wireless Protocol Analysis  
**CTF Event:** Unknown CTF (Consolidated under Unknown)  
**Artifacts:**
- `capture.pcap` (2,220 bytes Bluetooth Low Energy packet capture)  
**Status:** Solved / Complete Protocol Reconstruction  

---

## 1. Challenge Overview

The challenge provides a packet capture `capture.pcap` recording Bluetooth Low Energy (BLE) advertisement packets and GATT characteristic interactions with a smart audio peripheral advertising as **`NoiseGate Buds`** (firmware `fw1.4.2 [debug]`).

---

## 2. Packet Capture & Protocol Reverse Engineering

Detailed inspection of the 50 packets in `capture.pcap` extracts debug strings embedded in GATT characteristic descriptors and manufacturer advertisement payloads:

```text
provkey = adv mfg data (company 0x0f39) after the 0x01 type byte, 16 bytes
config@0x0021: plaintext = value XOR provkey (provkey repeated cyclically)
nonce = notify@0x0033
vault@0x0033: released after auth; plaintext = ct XOR ks, ks = sha256(provkey || nonce || byte(i)) for i=0,1,.. concatenated
```

### A. Phase 1: Provisioning Key Extraction
- The peripheral emits BLE legacy advertisement PDUs (`ADV_IND`).
- Within the Advertising Data (AD) structures:
  - AD Type `0xFF` (Manufacturer Specific Data) contains Company ID `0x0f39`.
  - Byte `0x01` indicates the provisioning data structure.
  - The subsequent 16 raw bytes represent `provkey`.

### B. Phase 2: Configuration Handle (`0x0021`) Decryption
- A GATT Read Request is issued against handle `0x0021`.
- The ciphertext value returned is decrypted by repeating `provkey` cyclically:
  $$P_{\text{config}}[k] = C_{\text{config}}[k] \oplus \text{provkey}[k \pmod{16}]$$

### C. Phase 3: Vault Notification (`0x0033`) Keystream Reconstruction
- Upon successful authentication, the peripheral emits a GATT Notification on handle `0x0033` containing an ephemeral `nonce`.
- The vault ciphertext payload is decrypted using a counter-mode keystream derived from repeated SHA-256 hashes:
  $$K_i = \text{SHA256}(\text{provkey} \parallel \text{nonce} \parallel \text{byte}(i)) \quad \text{for } i = 0, 1, 2, \dots$$
  $$\text{Keystream} = K_0 \parallel K_1 \parallel K_2 \dots$$
  $$P_{\text{vault}} = C_{\text{vault}} \oplus \text{Keystream}[0 : |C_{\text{vault}}|]$$

---

## 3. Decryption Implementation

```python
import hashlib

def decrypt_vault(provkey: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    keystream = bytearray()
    i = 0
    while len(keystream) < len(ciphertext):
        h = hashlib.sha256(provkey + nonce + bytes([i])).digest()
        keystream.extend(h)
        i += 1
        
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    return plaintext
```

Executing this routine over the extracted packet bytes decrypts the protected configuration and vault contents, recovering the challenge flag.
