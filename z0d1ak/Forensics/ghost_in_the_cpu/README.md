# Ghost in the GPU — CTF Challenge Writeup

## Challenge Overview
- **Category:** Forensics / Reverse Engineering / Hardware & GPU Memory
- **Challenge:** Ghost in the GPU (`ghost_in_the_gpu` / `ghost-in-the-gpu.zip`)
- **Handout:** `vram_dump.bin` (32 MB raw GPU VRAM dump)
- **Flag:** `zdk{mEmorY_13ak_f0und}`

---

## 1. Initial Analysis & Triage

The challenge provides a single binary artifact: `vram_dump.bin`, sized at exactly **33,554,432 bytes (32 MB)**.

Running traditional forensic tools (`file`, `strings`, `binwalk`, image magic scanners) returns mostly uninitialized data with pseudo-random byte distributions.

### Entropy & Data Distribution Analysis
Dividing the 32 MB file into 64 KB blocks and computing Shannon entropy across the binary reveals a distinct anomaly:

```python
import numpy as np

with open("vram_dump.bin", "rb") as f:
    data = f.read()

# Scan 64KB blocks for low entropy regions
for i in range(0, len(data), 65536):
    blk = data[i:i+65536]
    counts = np.bincount(np.frombuffer(blk, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(blk)
    entropy = -np.sum(probs * np.log2(probs))
    if entropy < 7.5:
        print(f"Offset 0x{i:08x}: entropy = {entropy:.4f}, unique bytes = {len(probs)}")
```

**Results:**
- Offsets `0x00000000` through `0x008FFFFF`: High entropy ($\sim 7.99$), uninitialized memory / random noise.
- Offsets **`0x00900000` through `0x00A7FFFF`** (total $1,572,864$ bytes / $1.5\text{ MB}$): Low entropy ($\sim 1.0 - 1.12$), containing only 2–3 distinct byte values.
- Offsets `0x00A80000` through `0x01FFFFFF`: High entropy random noise.

---

## 2. GPU Tensor & Data Format Identification

Examining the raw bytes in the region `0x00900000 - 0x00A80000`:
- Repeated byte sequence: `\x00\x3c` (`0x3c00`) and `\x00\xbc` (`0xbc00`).
- In **IEEE 754 half-precision float (`float16`)**:
  - `0x3c00` $\rightarrow +1.0$
  - `0xbc00` $\rightarrow -1.0$

### Tensor Dimensionality
Calculating the number of elements:
$$\text{Total Elements} = \frac{1,572,864\text{ bytes}}{2\text{ bytes per float16}} = 786,432\text{ elements}$$

Factoring $786,432$:
$$786,432 = 3 \times 262,144 = 3 \times (512 \times 512)$$

This corresponds to a standard **$3 \times 512 \times 512$ (RGB / planar tensor)** used by GPU machine learning frameworks (e.g. PyTorch / CUDA / Stable Diffusion image pipelines), with pixel values normalized to the range $[-1.0, 1.0]$.

---

## 3. Extraction & Reconstruction

Using NumPy and Pillow, we extract the three channels, denormalize $[-1.0, 1.0] \rightarrow [0, 255]$, and reconstruct the $512 \times 512$ RGB image.

### Solver Script (`solve_ghost.py`)

```python
import numpy as np
from PIL import Image

def solve(dump_path="vram_dump.bin", output_path="flag_extracted.png"):
    with open(dump_path, "rb") as f:
        f.seek(0x900000)
        raw_tensor = f.read(0x180000) # 1.5 MB (3 * 512 * 512 * 2 bytes)

    # Decode IEEE 754 float16
    f16 = np.frombuffer(raw_tensor, dtype=np.float16)
    
    # Reshape to (Channels=3, Height=512, Width=512)
    tensor = f16.reshape(3, 512, 512)
    
    # Map [-1.0, 1.0] -> [0, 255]
    img_data = ((tensor + 1.0) / 2.0 * 255).astype(np.uint8)
    
    # Transpose to HWC (512, 512, 3) for standard image representation
    rgb = np.transpose(img_data, (1, 2, 0))
    
    img = Image.fromarray(rgb)
    img.save(output_path)
    print(f"[+] Reconstructed image saved to {output_path}")

if __name__ == "__main__":
    solve()
```

---

## 4. Glyph & Character Disambiguation

Rendering the extracted image produces pixel-art text. A strict pixel-level inspection ensures zero ambiguity in leetspeak and letter casing:

```
+-------------------------------------------------------------+
| Glyph Index | Glyph Shape | Pixel Features     | Character  |
+-------------+-------------+--------------------+------------+
| 0           | 21px height | Top/bottom bars    | 'Z' or 'z' |
| 1           | 21px height | Right ascender     | 'd'        |
| 2           | 21px height | Left ascender      | 'k'        |
| 3           | 21px height | Open curly brace   | '{'        |
| 4           | 18px height | Double hump        | 'm'        |
| 5           | 21px height | 3 horizontal bars  | 'E'        |
| 6           | 18px height | Double hump        | 'm'        |
| 7           | 18px height | Loop, no slash     | 'o' (lower)|
| 8           | 18px height | Short stem & arc   | 'r'        |
| 9           | 21px height | Branch & stem      | 'Y' (upper)|
| 10          | 3px height  | Baseline dash      | '_'        |
| 11          | 21px height | Serif hook & base  | '1' (digit)|
| 12          | 21px height | Two curves         | '3' (digit)|
| 13          | 18px height | Loop & right tail  | 'a'        |
| 14          | 21px height | Left ascender      | 'k'        |
| 15          | 3px height  | Baseline dash      | '_'        |
| 16          | 21px height | Top hook & cross   | 'f'        |
| 17          | 21px height | Slashed zero       | '0' (digit)|
| 18          | 18px height | U-shape            | 'u'        |
| 19          | 18px height | Single hump        | 'n'        |
| 20          | 21px height | Right ascender     | 'd'        |
| 21          | 21px height | Close curly brace  | '}'        |
+-------------------------------------------------------------+
```

### Key Distinctions:
1. **`1` vs `l` in `13ak`**: Glyph 11 includes a distinct top-left hook/serif and a bottom baseline pad, identifying it conclusively as digit **`1`**.
2. **`o` vs `0` in `mEmorY`**: Glyph 7 has lowercase height (18px) and no inner diagonal bar (**`o`**), whereas Glyph 17 in `f0und` is full height (21px) with an explicit diagonal line through the center (**`0`**).

---

## 5. Final Flag

```
zdk{mEmorY_13ak_f0und}
```
