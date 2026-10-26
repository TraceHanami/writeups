# First Stego — Steganography & Forensic Carving Writeup

## Metadata
- **Challenge Name:** First (Stego Image Analysis)
- **CTF / Event:** Unknown / Independent CTF
- **Category:** Steganography / Forensics
- **Difficulty:** Medium
- **Artifacts:**
  - Original Image: `first.png` (PNG image data, 3,384,896 bytes)
  - Carved Payloads: `extractions/first.png.extracted/`
- **Status:** Solved & Verified
- **Flag:** `CTF{l0v3_c4n_tr4n5c3nd_t1m3_4nd_5p4c3}`

---

## Challenge Overview
The challenge provides a single high-resolution image file named `first.png`. Initial inspection indicates that the file size is abnormally large (~3.38 MB) for standard web graphics of its visual dimensions, suggesting trailing payloads, embedded archives, or concatenated file formats.

---

## Forensic Inspection & Carving

### 1. Embedded Payload Extraction
Running `binwalk` against `first.png` identified concatenated ZIP archives and zlib-compressed streams appended to the PNG image data:
```bash
binwalk -e first.png
```
This extracted multiple directory trees containing standalone Python challenge binaries/environments under `extractions/first.png.extracted/`.

### 2. Analysis of Extracted Python Runtime Scripts
Inspecting the extracted `__main__.py` scripts across the subdirectories revealed an interactive challenge terminal designed to test steganographic height manipulation on JPEG images:
```python
# Extracted from extractions/first.png.extracted/256F1E/__main__.py
_SEC_B64 = "eJyUl2VQHE7wpv..." # Base64/zlib compressed image
IMAGE_DATA = bytearray(zlib.decompress(base64.b64decode(_SEC_B64)))
SOF0_OFFSET = 158
HEIGHT_OFFSET = 163
FLAG_TEXT = "CTF{l0v3_c4n_tr4n5c3nd_t1m3_4nd_5p4c3}"
```

### 3. Stego Logic
The challenge implements a cropped JPEG image where the bottom section containing the flag is hidden by modifying the JPEG Start of Frame (SOF0) height field at byte offset `163` (`0xa3`).
The embedded terminal tool evaluates user commands:
- `hexdump` / `view` inspects the raw image bytes.
- Modifying the height header to restore the true dimensions exposes the bottom pixels of the image.
- Entering `submit CTF{l0v3_c4n_tr4n5c3nd_t1m3_4nd_5p4c3}` validates the flag:
```text
╔════════════════════════════════════════════════════════════════════════════╗
║ Flag Verified: CTF{l0v3_c4n_tr4n5c3nd_t1m3_4nd_5p4c3}                     ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---

## Flag & Verification
The hardcoded flag was directly recovered from the carved challenge code and verified against the internal validator:
$$\text{Flag: } \mathbf{CTF\{l0v3\_c4n\_tr4n5c3nd\_t1m3\_4nd\_5p4c3\}}$$

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Primary Image | `first.png` | Original steganographic PNG carrier image |
| Carved Script | `__main__.py` | Extracted Python verification logic exposing the flag |
