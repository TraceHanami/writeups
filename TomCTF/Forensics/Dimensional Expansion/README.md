## TomCTF Writeup: Dimensional Expansion

Welcome back, hackers. Today we’re tackling a challenge that literally requires you to "think bigger." This challenge, **Dimensional Expansion**, is a classic example of **IHDR/SOF manipulation**. It forces you to question the integrity of what you see and realize that an image's canvas isn't always as large as the file says it is.

If you've ever felt like a piece of a puzzle was missing, it’s probably because it was hidden just outside the frame.

### **What You'll Learn**

- **JPEG Header Structure:** Identifying the Start of Frame (SOF) marker.
- **Aspect Ratio Manipulation:** How to uncover hidden data by expanding image dimensions.
- **Hex Editing:** Manually patching binary files to bypass metadata limits.
- **MCU Logic:** Understanding why non-standard heights are a major red flag in forensics.

### **Tools Used**

- **ExifTool:** For initial metadata and dimension inspection.
- **Hex Editor (Ghex or hexeditor):** To manually patch the SOF0 marker.
- **Python 3:** For automated binary patching.

---

### **Challenge Overview**

- **Event:** TomCTF
- **Category:** Forensics / Steganography
- **Difficulty:** Easy
- **Designer:** TraceHanami
- **Description:** You become stronger when you push past your limits. Don’t worry about it. Just break your limits.

![Original Image](original.png)

---

### **Step-by-Step Walkthrough**

### **Step 1: Analyzing the "Limits"**

We start by inspecting the provided file, `push-past-your-limits.jpg`. The description repeatedly mentions "limits" and "breaking boundaries." In image forensics, this almost always points to **image dimensions**.

Running `exiftool` reveals:

- **Image Width:** 720
- **Image Height:** 647

### **Step 2: Spotting the Red Flag**

JPEG images are compressed in **Minimum Coded Units (MCUs)**, typically 8x8 or 16x16 blocks.
647÷8=80.875

Because 647 is not a multiple of 8, it suggests the image was "cut off" mid-block. This is a deliberate sign that the height value has been tampered with to hide a secret at the bottom of the image.

### **Step 3: Locating the SOF0 Marker**

To fix the height, we need to find the **Start of Frame (SOF0)** marker in the hex data. This marker defines the actual height and width used by the viewer.

1. Open the file in a hex editor.
2. Search for the hex string `FF C0`.
3. Following the marker and the length bytes, we find the dimensions:
`FF C0 00 11 08 02 87 02 D0`
    - `02 87` (Hex) = 647 (Decimal Height)
    - `02 D0` (Hex) = 720 (Decimal Width)

### **Step 4: Breaking the Limits**

To reveal the hidden data, we need to "push" the height. Changing `02 87` to something significantly larger, like `04 A0` (1184), will tell the image viewer to keep rendering the data stream further down.

---

### **Solution Methods**

**Method A: The Python Patch (Automation)**
We can use a one-liner to find the marker and overwrite the height bytes automatically.

**Python**

```python
d = bytearray(open("push-past-your-limits.jpg", "rb").read())
m = d.find(b"\xff\xc0")
d[m+5:m+7] = b"\x04\xa0"
open("flag_found.jpg", "wb").write(d)
```

**Method B: Manual Hex Edit (Precision)**

1. Open `hexeditor push-past-your-limits.jpg`.
2. Locate the `FF C0` segment.
3. Change the bytes at the height offset from `02 87` to `04 A0`.
4. Save and exit.

![Decryption Result](result.png)

---

### **The Result**

Upon reopening the modified image, the bottom of the canvas expands, revealing the hidden flag that was previously "below the limit."

**Flag:** `tomctf{d1m3ns1onal_5t3g0_unl0ck3d}`

### **Final Thoughts**

This challenge proves that what you see is only what the header allows you to see. By understanding the structural bytes of a JPEG, you can bypass the "limits" set by the creator and reveal the full picture.

Happy hacking, and I'll see you in the next write-up!
**Cheers, TraceHanami**
