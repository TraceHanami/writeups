# You Have Not Seen My Colors — CTF Writeup

**Category:** Cryptography / Steganography  
**Challenge:** You Have Not Seen My Colors (`crypto_you-have-not-seen-my-colors`)  
**Author:** TitanCode  
**Event:** z0d1ak CTF  
**Points:** 265  
**Flag:** `zdk{ma5TER_0f_coLOR5_aNd_ctF}`

---

## 1. Challenge Overview

The challenge description states:
> *Elian gave you this challenge. Find meaning in the noise, then prove what you decoded to the private endpoint.*  
> *The answer is lowercase with words joined by underscores.*

We are given a single file: `image.png` (a 100×100 RGB image) and a remote endpoint at `https://unseen-colors-585a4cc93b0f.chals.z0d1ak.org`.

---

## 2. Statistical Analysis & Steganography Detection

Opening `image.png` visually presents what looks like pure static RGB noise.

When analyzing the histogram and distribution of byte values across each color channel ($R, G, B \in [0, 255]$):

```python
from PIL import Image
import numpy as np

img = Image.open('image.png')
arr = np.array(img)

for name, ch_idx in [('Red', 0), ('Green', 1), ('Blue', 2)]:
    counts = np.bincount(arr[:, :, ch_idx].flatten(), minlength=256)
    print(f"[{name}] Unique values: {np.count_nonzero(counts)} | Count of 0: {counts[0]} | Mean: {arr[:, :, ch_idx].mean():.2f}")
```

**Results:**
- **Red:** Values strictly in $[1, 255]$ (0 never occurs).
- **Green:** Values strictly in $[1, 255]$ (0 never occurs).
- **Blue:** Values in $[0, 255]$. Value `0` occurs **166 times** (while every other byte value has a uniform ~39 occurrences).

The title *"You Have Not Seen My Colors"* is a direct hint to the zeroed/unseen Blue channel ($B = 0$).

---

## 3. Isolating the Hidden Text

Filtering pixels where $B = 0$ isolates the foreground glyphs:

```python
from PIL import Image
import numpy as np

img = Image.open('image.png')
arr = np.array(img)

# Foreground mask
mask = (arr[:, :, 2] == 0)

# Render ASCII preview
for r in range(100):
    row = ''.join(['#' if mask[r, c] else ' ' for c in range(100)])
    if '#' in row:
        print(f"{r:2d}: {row}")
```

This reveals four distinct lines of geometric characters:

```text
Line 1 (rows 1..4):
####...........####..........####
#..............#..#.............#
#..............#..#.............#
########.#.....#..#......########

Line 2 (rows 11..18):
####......####.....########..................................
#..#.........#............#........#.####.....####...#.......
#..#.........#............#.............#.....#..#...#.......
#..#.........#............#.............#.....#..#...#.......
...#........................#....########.....####...########
...#
...#
...#

Line 3 (rows 24..31):
#................
#................
#................
#............#..#
#..#.........#..#
#..#.........#..#
#..#.........####
####.............

Line 4 (rows 36..39):
...#.........#.####.........#..#
...#..............#.........#..#
...#..............#.........#..#
####.......########.........####
```

---

## 4. Deciphering Elian Script

The name **"Elian"** in the description refers to **Elian Script**, a cipher based on a 3×3 grid:

```text
Cycle 1 (Equal lines):
A B C
D E F
G H I

Cycle 2 (Unequal / elongated lines):
J K L
M N O
P Q R

Cycle 3 (Unequal lines + Dot marker):
S T U
V W X
Y Z
```

### Grid Layout:
- **Box 1 (A/J/S):** `┐` (Ceiling + Right wall)
- **Box 2 (B/K/T):** `⊐` (Top + Right + Bottom)
- **Box 3 (C/L/U):** `┘` (Right + Bottom)
- **Box 4 (D/M/V):** `⊓` (Left + Top + Right)
- **Box 5 (E/N/W):** `▢` (Full 4-sided enclosure)
- **Box 6 (F/O/X):** `⊔` (Left + Bottom + Right)
- **Box 7 (G/P/Y):** `┌` (Left + Top)
- **Box 8 (H/Q/Z):** `⊏` (Left + Top + Bottom)
- **Box 9 (I/R):** `└` (Left + Bottom)

---

### Step-by-Step Translation:

1. **Line 1:**
   - Char 1: `⊏` with elongated bottom line + dot $\rightarrow$ **Z** (Box 8, Cycle 3)
   - Char 2: `⊓` with equal lines $\rightarrow$ **D** (Box 4, Cycle 1)
   - Char 3: `⊐` with elongated bottom line $\rightarrow$ **K** (Box 2, Cycle 2)  
   $\rightarrow$ **`zdk`**

2. **Line 2:**
   - Char 1: `⊓` with elongated right line $\rightarrow$ **M** (Box 4, Cycle 2)
   - Char 2: `┐` with equal lines $\rightarrow$ **A** (Box 1, Cycle 1)
   - Char 3: `┐` with elongated top line + dot $\rightarrow$ **S** (Box 1, Cycle 3)
   - Char 4: `⊐` with elongated bottom line + dot $\rightarrow$ **T** (Box 2, Cycle 3)
   - Char 5: `▢` full square $\rightarrow$ **E** (Box 5, Cycle 1)
   - Char 6: `└` with elongated bottom line $\rightarrow$ **R** (Box 9, Cycle 2)  
   $\rightarrow$ **`master`**

3. **Line 3:**
   - Char 1: `⊔` with elongated left line $\rightarrow$ **O** (Box 6, Cycle 2)
   - Char 2: `⊔` with equal lines $\rightarrow$ **F** (Box 6, Cycle 1)  
   $\rightarrow$ **`of`**

4. **Line 4:**
   - Char 1: `┘` with equal lines $\rightarrow$ **C** (Box 3, Cycle 1)
   - Char 2: `⊐` with elongated bottom line + dot $\rightarrow$ **T** (Box 2, Cycle 3)
   - Char 3: `⊔` with equal lines $\rightarrow$ **F** (Box 6, Cycle 1)  
   $\rightarrow$ **`ctf`**

Combined decoded phrase: **`master of ctf`**

---

## 5. Submission & Flag Retrieval

Formatting as lowercase with underscores: `master_of_ctf`.

Submitting via POST request:
```bash
curl -X POST https://unseen-colors-585a4cc93b0f.chals.z0d1ak.org/solve \
     -d "answer=master_of_ctf"
```

**Response:**
```json
{"flag":"zdk{ma5TER_0f_coLOR5_aNd_ctF}"}
```

---

## 6. Flag

```
zdk{ma5TER_0f_coLOR5_aNd_ctF}
```
