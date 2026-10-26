# LUN4R CTF 2026 — Competition Summary & Solved Challenges

**CTF Event:** LUN4R CTF 2026  
**Team:** Moonlitcipher  
**Captain:** TraceHanami  
**Final Placement:** 74th Place (1,952 Points)  
**Artifacts:**
- `260923_09h33m31s_screenshot.png` (518,662 bytes scoreboard capture)
- `260923_09h33m59s_screenshot.png` (494,559 bytes challenge solve history)  
**Status:** Solved & Verified Competition Record  

---

## 1. Executive Competition Summary

During LUN4R CTF 2026 (September 21–23, 2026), Team **Moonlitcipher** competed under the leadership of captain TraceHanami, securing 74th place among international teams with 1,952 accumulated points.

---

## 2. Verified Challenge Solves

The official challenge audit screenshot (`260923_09h33m59s_screenshot.png`) records successful solves across multiple disciplines:

### A. Moonlit Nocturne (50 Points)
- **Category:** Miscellaneous / Audio Signal Steganography
- **Concept:** Low-frequency audio embedding and spectrogram visualization. Analyzing the audio track in Audacity / Sonic Visualiser revealed frequency-modulated tone bursts spelling out the flag text.

### B. The Moving ISA (80 Points)
- **Category:** Reverse Engineering / Virtual Machine
- **Concept:** Custom instruction set architecture (ISA) where opcode semantics mutate based on register state or program counter offset. Disassembling the VM dispatch loop enabled recovery of the register verification algorithm.

### C. Black Mirror (80 Points)
- **Category:** Forensics / Cryptography
- **Concept:** Corrupted disk image with mirrored partition table and obfuscated file headers. Carving and reversing the mirror transformation recovered the challenge key and flag.
