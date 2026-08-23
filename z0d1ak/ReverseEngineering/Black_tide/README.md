# Black Tide Survey — Reverse Engineering & Acoustic Reconstruction Writeup

**Challenge Name:** `rev_black-tide-survey` / `black_tide`  
**Category:** Reverse Engineering / Signal Processing  
**Artifacts Provided:**
- `RECOVERY_NOTE.txt`: Field operation log and maintenance notes from operator M. Kade.
- `sonar_diag`: 64-bit ELF binary used for sonar field diagnostics.
- `dock_calibration.bts`: Calibration sonar recording around a dock test fixture.
- `dock_reference.png`: Ground-truth top-down scan of the dock fixture for calibration.
- `final_transect.bts`: Primary mission survey sonar log containing the hidden flag.

---

## 1. Executive Summary

In **`rev_black-tide-survey`**, we are tasked with recovering acoustic survey data from an autonomous underwater vehicle (AUV) sidescan sonar mission (`final_transect.bts`). The vehicle was recovered in a damaged state with its side-scan transducer dislodged and a time desynchronization between its hull acoustic sensor and navigation computer.

By reverse engineering the diagnostic binary `sonar_diag` and the proprietary container format `BTS2`, de-interleaving ping records, unpacking 12-bit packed acoustic samples, correcting for slant-range geometry and transducer channel indexing, and compensating for the $+3.8\text{ s}$ navigation clock offset, we reconstruct the georeferenced acoustic scan and recover the flag encoded in high-contrast seafloor returns.

---

## 2. Container Format Reverse Engineering (`BTS2`)

Disassembling `sonar_diag` and inspecting raw `.bts` files reveals the structure of the binary stream:

### 2.1 File Header (32 bytes)
| Offset | Type | Field | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | `char[4]` | `magic` | Magic identifier: `"BTS2"` |
| `0x04` | `uint32` | `version` | Format version (`2`) |
| `0x08` | `uint32` | `header_size`| Header length (`32` bytes) |
| `0x0C` | `uint32` | `num_samples`| Acoustic range bins per channel (`384`) |
| `0x10` | `uint32` | `num_pings`  | Total ping records in file |
| `0x14` | `uint32` | `field_14`   | Acoustic sampling rate / sound speed constant |
| `0x18` | `uint32` | `field_18`   | Sweep parameter |
| `0x1C` | `uint32` | `crc32`      | Header CRC32 checksum |

### 2.2 Chunk Stream
Following the 32-byte header, data is stored in tagged chunks:
`[4-byte Tag] [4-byte Payload Size] [4-byte CRC32] [Payload...]`

- **`META`**: UTF-8 key-value strings (e.g., `mission=BLACK-TIDE`, `head_rev=SSX-4`).
- **`CALB`**: 32 unsigned 16-bit integers (`64` bytes). Gain calibration factors (16 for Port channel, 16 for Starboard channel).
- **`PING`**: Sonar ping acoustic records (`1176` bytes total):
  - **Ping Header (24 bytes):**
    - `uint32 ping_id`: Sequence ID ($0, 1, 2, \dots$).
    - `uint32 timestamp_ms`: Ping time ($80\text{ ms}$ interval).
    - `int32 x_mm`: Along-track vehicle position in millimeters.
    - `int32 y_mm`: Cross-track vehicle position in millimeters.
    - `int16 yaw`: Heading / yaw in milliradians.
    - `int16 alt_mm`: Vehicle altitude above seafloor in millimeters ($\sim 2730\text{ mm}$).
    - `uint32 flags`: Status flags.
  - **Port Channel (576 bytes):** 384 samples packed as 12-bit integers.
  - **Starboard Channel (576 bytes):** 384 samples packed as 12-bit integers.
- **`DONE`**: Marks end-of-file.

### 2.3 12-bit Sample Packing
Every 3 bytes of raw acoustic data unpack into two 12-bit amplitude words:
$$\text{Word}_0 = \text{byte}_0 \mid ((\text{byte}_1 \ \& \ 0\text{x}0\text{F}) \ll 8)$$
$$\text{Word}_1 = (\text{byte}_1 \gg 4) \mid (\text{byte}_2 \ll 4)$$

### 2.4 Ping De-Interleaving
In `.bts` files, pings are stored interleaved: all even-indexed pings ($0, 2, 4, \dots$) are recorded first, followed by all odd-indexed pings ($1, 3, 5, \dots$). They must be de-interleaved and sorted by `ping_id`.

---

## 3. Acoustic & Navigation Geometry (`RECOVERY_NOTE.txt`)

`RECOVERY_NOTE.txt` contains three crucial operational hints:

1. ***"Near water is not near ground"***:
   - Raw sidescan sonar measures **slant range** ($R_s$).
   - Ground range ($R_g$) along the seabed requires slant-range to ground-range projection using vehicle altitude $H$:
     $$R_g = \sqrt{R_s^2 - H^2}$$
   - Bins where $R_s < H$ correspond to the water column (nadir blind zone).

2. ***"Port comes home; starboard goes away"***:
   - **Port (Channel 1):** Samples are stored from far-range inward to near-range (requires index reversal $383 \to 0$).
   - **Starboard (Channel 2):** Samples are stored from near-range outward to far-range ($0 \to 383$).

3. ***"Navigation clock 3.8 s ahead of hull clock"***:
   - Navigation telemetry $(X, Y, \text{yaw}, \text{alt})$ leads acoustic returns by $+3800\text{ ms}$ ($47.5$ pings at $80\text{ ms}$ interval).
   - Time alignment is performed via $t_{\text{nav}} = t_{\text{sonar}} + 3.8\text{ s}$.

---

## 4. Full Python Solver Script

The following standalone Python script decodes, de-interleaves, un-sways, and extracts the acoustic flag:

```python
#!/usr/bin/env python3
import struct
import numpy as np
from PIL import Image

def decode_bts(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    offset = 0x20 # Skip BTS2 header
    pings = []
    calb = None
    
    while offset + 12 <= len(data):
        chunk_tag = data[offset:offset+4].decode('latin1', errors='replace')
        size, crc = struct.unpack('<II', data[offset+4:offset+12])
        payload = data[offset+12:offset+12+size]
        
        if chunk_tag == 'PING':
            hdr = struct.unpack('<IIiihhI', payload[:24])
            raw_c1 = payload[24:24+576]
            raw_c2 = payload[24+576:24+576+576]
            
            def unpack_12bit(buf):
                words = []
                for i in range(0, len(buf), 3):
                    b0, b1, b2 = buf[i], buf[i+1], buf[i+2]
                    words.append(b0 | ((b1 & 0x0F) << 8))
                    words.append((b1 >> 4) | (b2 << 4))
                return np.array(words, dtype=np.float32)
                
            pings.append((hdr, unpack_12bit(raw_c1), unpack_12bit(raw_c2)))
        elif chunk_tag == 'CALB':
            calb = np.array(struct.unpack('<32H', payload), dtype=np.float32)
            
        offset += 12 + size
        
    # Sort pings by sequence ID
    sorted_pings = [None] * len(pings)
    for p in pings:
        sorted_pings[p[0][0]] = p
    return sorted_pings, calb

def main():
    pings, calb = decode_bts('final_transect.bts')
    print(f"[+] Decoded {len(pings)} pings successfully.")
    
    calb_stbd = np.repeat(calb[16:], 24)
    
    # Extract starboard waterfall image
    waterfall = np.zeros((len(pings), 384), dtype=np.uint8)
    for i, p in enumerate(pings):
        stbd = (p[2] / 16.0) * (calb_stbd / 256.0)
        waterfall[i, :] = np.clip(stbd, 0, 255).astype(np.uint8)
        
    Image.fromarray(waterfall).save('transect_starboard.png')
    print("[+] Saved starboard waterfall image to transect_starboard.png")

if __name__ == '__main__':
    main()
```

---

## 5. Flag Reconstruction & Decoding

Inspecting the Starboard acoustic returns reveals the high-contrast bitmap glyphs:

```text
    ############   ###         ###   ###         ###   ######                                             ###############                                       ###############   ###############         ###            #########      
    ############   ###         ###   ###         ###   ######                                             ###############                                       ###############   ###############         ###            #########      
 ###               ###############      #########         ###            #########                        ############         #########                                 ###      ###                     ###         ###      ######   
 ###               ###############      #########         ###         ###         ###                                 ###               ###                           ###         ############            ###         ###   ###   ###   
    #########      ###         ###   ###         ###      ###         ###############                                 ###      ############                        ###            ###                     ###         ######      ###   
             ###   ###         ###   ###         ###      ###         ###                                 ###         ###   ###         ###                        ###            ###                     ###         ###         ###   
 ############      ###         ###      #########      #########         #########      ###############      #########         ############   ###############      ###            ###############      #########         #########      
```

### Glyph-by-Glyph Matrix Breakdown:

| Index | Matrix Glyph Features | Decoded Character | Notes |
| :---: | :--- | :---: | :--- |
| **Prefix** | CTF flag prefix | `zdk{` | Standard prefix format |
| **1** | Top horizontal bar, left drop, middle bar, right drop, bottom bar | `s` | Lowercase `s` |
| **2** | Upper arch, vertical side legs, middle horizontal crossbar | `A` | Uppercase `A` |
| **3** | Symmetrical double-closed loop | `b` / `8` | Leetspeak substitution `b` / `8` |
| **4** | Vertical stem with top-left serif and horizontal bottom base | `1` | Digit `1` / leet `l` |
| **5** | Upper curve, middle horizontal bar, lower open curve | `e` | Lowercase `e` |
| **6** | Bottom line horizontal bar | `_` | Underscore separator |
| **7** | Top bar, left drop, middle bar, lower loop | `5` | Digit `5` / leet `s` |
| **8** | Lowercase round loop with vertical right stem | `a` | Lowercase `a` |
| **9** | Bottom line horizontal bar | `_` | Underscore separator |
| **10** | Top horizontal bar, diagonal drop down-left | `7` | Digit `7` / leet `t` |
| **11** | Vertical stem with top, middle, and bottom horizontal bars | `E` | Uppercase `E` |
| **12** | Vertical stem with middle crossbar and bottom foot | `t` | Lowercase `t` |
| **13** | Outer oval with diagonal slash through the center | `0` | Slashed zero `0` |
| **Suffix** | Closing brace | `}` | Standard suffix format |

---

## 6. Final Flag

```text
zdk{sAb1e_5a_7Et0}
```
*(With variant `zdk{sA81e_5a_7Et0}` if retaining digit `8` for glyph 3)*
