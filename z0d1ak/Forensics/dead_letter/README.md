# Forensics: Dead Letter Wake — Writeup

## Challenge Information
- **Category:** Forensics / Network & Mail Forensics / Visual Redaction Reversal
- **Provided Files:** `forensics_dead-letter-wake.zip`
  - `evidence/dead-letter.pcap`
  - `evidence/mail-queue.tar.gz`
- **Flag Format:** `zdk{...}`

---

## 1. Initial Analysis & Reconnaissance

Extracting `forensics_dead-letter-wake.zip` gives us two primary forensic artifacts:
1. `dead-letter.pcap` — A packet capture of SMTP network communications.
2. `mail-queue.tar.gz` — An archive containing postfix spool data (`mail.log` and a deferred queue directory).

### Inspecting `mail.log`
Inspecting `mail.log` reveals the following journal entries:
```text
Aug 17 02:31:36 mx postfix/smtpd[6214]: connect from spooler.pelagos.invalid[10.44.0.77]:41404
Aug 17 02:31:36 mx postfix/smtpd[6214]: Anonymous TLS connection established from spooler.pelagos.invalid[10.44.0.77]: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384
Aug 17 02:31:37 mx postfix/cleanup[6220]: DLW214704: message-id=<2147-recovery.part4@relay.pelagos.invalid>
Aug 17 02:31:37 mx postfix/qmgr[940]: DLW214704: from=<watch@pelagos.invalid>, size=17122, nrcpt=1 (queue active)
Aug 17 02:32:07 mx postfix/smtp[6227]: DLW214704: to=<archive@blacktide.invalid>, relay=none, delay=30, status=deferred (connect to archive.blacktide.invalid timed out)
```

Key observations:
- A message series identified as `2147-recovery` was sent in parts.
- Part 4 (`2147-recovery.part4@relay.pelagos.invalid`) was transmitted over TLS (encrypted) and failed delivery, landing in the Postfix deferred queue as `deferred/DLW214704.eml`.
- Inspecting `dead-letter.pcap` with `tshark` reveals the remaining parts (Parts 1, 2, 3, 5, 6, 7) transmitted over unencrypted SMTP TCP streams.

---

## 2. Reconstructing the Multipart Message (RFC 2046 `message/partial`)

The emails use MIME `message/partial` to fragment a single large message across multiple transmissions:
- Header: `Content-Type: message/partial; id="<wake.2147.deadletter@relay.pelagos.invalid>"; number=X; total=7`

Mapping of the parts:
- **Part 1:** TCP Stream 1
- **Part 2:** TCP Stream 6
- **Part 3:** TCP Stream 3
- **Part 4:** `deferred/DLW214704.eml`
- **Part 5:** TCP Stream 8
- **Part 6:** TCP Stream 11
- **Part 7:** TCP Stream 12

### Reassembly Script
We extract the payload data for parts 1, 2, 3, 5, 6, 7 from the PCAP and combine them with part 4 from the deferred queue file:

```python
import subprocess, email

pcap_path = 'extracted_dead_letter_wake/dead-letter-wake/evidence/dead-letter.pcap'

def get_client_payload(stream_id):
    cmd = [
        'tshark', '-r', pcap_path,
        '-Y', f'tcp.stream == {stream_id} && tcp.dstport == 25',
        '-T', 'fields', '-e', 'tcp.payload'
    ]
    out = subprocess.check_output(cmd).decode('ascii', errors='ignore')
    payloads = [bytes.fromhex(line.strip()) for line in out.splitlines() if line.strip()]
    return b''.join(payloads)

streams_map = {1: 1, 2: 6, 3: 3, 4: None, 5: 8, 6: 11, 7: 12}
parts = {}

with open('extracted_dead_letter_wake/dead-letter-wake/evidence/deferred/DLW214704.eml', 'rb') as f:
    dlw4 = f.read()

for p in range(1, 8):
    if streams_map[p] is not None:
        raw = get_client_payload(streams_map[p])
        # Strip SMTP DATA framing
        data = raw[raw.find(b'DATA\r\n') + 6:]
        if data.endswith(b'\r\n.\r\n'):
            data = data[:-5]
        parts[p] = data.split(b'\r\n\r\n', 1)[1]
    else:
        parts[p] = dlw4.split(b'\r\n\r\n', 1)[1]

# Reassemble the complete MIME email
reassembled_email = b''.join([parts[p] for p in range(1, 8)])

# Extract attachment
msg = email.message_from_bytes(reassembled_email)
for part in msg.walk():
    if part.get_filename() == 'recovery-authorization.pdf':
        with open('recovery-authorization.pdf', 'wb') as f:
            f.write(part.get_payload(decode=True))
        print("[+] Successfully extracted recovery-authorization.pdf")
```

---

## 3. Investigating `recovery-authorization.pdf`

Extracting images from the PDF using `pdfimages`:
```bash
pdfimages -png recovery-authorization.pdf img_extracted
```
This produces two PNG images:
1. `img_extracted-000.png` (`744x56` px) — The mosaiced authorization key.
2. `img_extracted-001.png` (`1904x256` px) — The reference calibration strip.

The document's text states:
> *"The authorization key below was mosaiced before the source text layer was discarded. The pale acquisition bands are part of the target crop."*  
> *"Calibration capture - PIX-8 / gamma-encoded RGB / same renderer / do not resample"*

---

## 4. Reversing the Mosaic (Depix / Block Matching)

- **Font:** Monospaced `Courier-Bold` 11pt
- **Block Size:** `8x8` pixels (Mosaic dimension: `93` columns x `7` rows)
- **Character Pitch:** ~`19.04` pixels (~`2.38` blocks per character)
- **Target String Length:** 38 characters

By analyzing the horizontal baseline and bottom-row block profiles:
- Underscore delimiters (`_`) appear with distinctive bottom-row ink (`y=32..40`) at block columns 21, 40, 54, 68, 78.
- The word lengths between underscores are:
  - `D3Ad` (4 chars)
  - `Let7ERS` (7 chars)
  - `spEAk` (5 chars)
  - `aFT3r` (5 chars)
  - `7hE` (3 chars)
  - `waKe` (4 chars)

Combining the matched leet-speak casing and character sequences yields:
`D3Ad_Let7ERS_spEAk_aFT3r_7hE_waKe`

---

## 5. Final Flag

```text
zdk{D3Ad_Let7ERS_spEAk_aFT3r_7hE_waKe}
```
