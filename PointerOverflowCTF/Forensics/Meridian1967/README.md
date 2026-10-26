# Pointer Overflow CTF — Meridian Data Processing Services: Batch #1162

**Category:** Steganography / Punchcard Forensics  
**CTF Event:** Pointer Overflow CTF 2026  
**Artifacts:**
- `job-ticket-1162.pdf` (45,355 bytes)
- `job-ticket-1162.txt` (1,183 bytes)
- `ticket-1.png` (221,595 bytes)
- `ticket-2.png` (56,789 bytes)
- `metadata-a.png` (44,864 bytes)
- `metadata-b.png` (29,074 bytes)
- `261013_11h44m30s_screenshot.png` (24,720 bytes)  
**Status:** In-Progress / Preliminary Writeup  

---

## 1. Challenge Overview

Participants receive a memorandum from "Meridian Data Processing Services", dated November 14, 1967, regarding **Batch Ledger #1162**. The batch consists of two IBM 80-column punched card job tickets (Suffix A and Suffix B):
```text
MERIDIAN DATA PROCESSING SERVICES
445 SEVENTH AVENUE | NEW YORK | MURRAY HILL 8-4400

REF: BATCH LEDGER #1162

Each card follows our customary interleave: the sixteen-character
NONCE is distributed through the payload region at the stride
indicated by the PAT marker in the card metadata. Combine
Ticket A and Ticket B according to the job control spec.
```

---

## 2. Artifact Breakdown

1. **`job-ticket-1162.pdf` & `.txt`:** Specification memo detailing the 16-character NONCE distribution rule, the stride extracted from the `PAT` marker in metadata, and column interleave format.
2. **`ticket-1.png` & `ticket-2.png`:** High-resolution scans of the punched card tickets.
3. **`metadata-a.png` & `metadata-b.png`:** Header and footer metadata crops indicating batch ledger numbers, job control cards, and the `PAT` stride parameter.
4. **`261013_11h44m30s_screenshot.png`:** Work-in-progress desktop crop verifying punch row alignments (`BATCH 1162-A`).

---

## 3. Punchcard Decoding Architecture

Standard IBM 80-column punch cards encode characters using Hollerith code:
- **Rows:** 12, 11 (zone punches 0-zone, 11-zone, 12-zone) and numeric digits 0 through 9.
- **Columns:** 80 columns per card representing 80 ASCII / EBCDIC characters.

### Deinterleaving Algorithm:
1. Decode each column (1 to 80) of Ticket A and Ticket B into its corresponding Hollerith character.
2. Parse the `PAT` stride parameter $S$ from `metadata-a.png`.
3. Extract the 16-byte nonce distributed at stride $S$ across the payload columns.
4. Concatenate and XOR/de-interleave the payload characters from Ticket A and Ticket B according to the batch processing specification to yield the flag.
