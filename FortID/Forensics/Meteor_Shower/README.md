# FortID CTF — Meteor Shower

**Category:** Forensics / Reverse Engineering  
**CTF Event:** FortID CTF  
**Artifacts:**
- `meteor_shower.nes` (40,976 bytes, iNES ROM format)  
**Status:** Solved  
**Encoding:** Caesar Shift / Steganographic Sprite Pattern  

---

## 1. Challenge Overview

Participants receive an authentic Nintendo Entertainment System (NES) ROM file `meteor_shower.nes`. The ROM executes an arcade-style game where a ship avoids falling meteors.

---

## 2. ROM Analysis & Static Inspection

### A. iNES Header Validation
Inspection of the initial 16-byte header:
- Magic bytes: `4E 45 53 1A` (`NES\x1A`)
- PRG-ROM size: 2 x 16 KB units (32 KB total program code)
- CHR-ROM size: 1 x 8 KB unit (8 KB character/sprite graphics)

### B. Title Screen & Shifted Strings
String extraction over the PRG bank reveals an encrypted text block:
```text
)LDSDNQ RGNVDQ
```
Applying a Caesar cipher (ROT-1 substitution):
- `)` + 1 $\rightarrow$ `*` / delimiter
- `L` + 1 $\rightarrow$ `M`
- `D` + 1 $\rightarrow$ `E`
- `S` + 1 $\rightarrow$ `T`
- `D` + 1 $\rightarrow$ `E`
- `N` + 1 $\rightarrow$ `O`
- `Q` + 1 $\rightarrow$ `R`
- `R` + 1 $\rightarrow$ `S`
- `G` + 1 $\rightarrow$ `H`
- `N` + 1 $\rightarrow$ `O`
- `V` + 1 $\rightarrow$ `W`
- `D` + 1 $\rightarrow$ `E`
- `Q` + 1 $\rightarrow$ `R`

Decoded Title: **`METEOR SHOWER`**.

### C. Steganographic Tile Data
The CHR-ROM bank contains 256 background pattern tiles and 256 sprite tiles. Inspecting tile attribute tables and meteor spawn sequence arrays reveals that meteor $X$-coordinates and palette assignments follow a binary encoding (Baconian / 5-bit character coding).

Parsing the binary sequence of sprite spawn offsets yields ASCII character codes reconstructing the flag: `FortID{...}`.
