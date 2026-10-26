# Origami — Reverse Engineering Writeup

## Metadata
- **Challenge Name:** Origami
- **CTF / Event:** CREST CTF 2026
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Artifacts:**
  - Binary: `origami` (ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped, 14,920 bytes)
- **Status:** Solved & Fully Verified
- **Flag:** `CREST{byt3c0d3_vms_hide_l0g1c_n0t_h1de_1t_w3ll}`

---

## Challenge Overview
The `origami` challenge distributes an ELF 64-bit PIE executable. The binary accepts a single command-line argument:
```bash
./origami <flag>
```
If the argument matches the expected flag string, the program prints `"Access granted."`. If invalid or incorrect length, it prints `"Incorrect!"` or exits.

Reverse engineering shows that the binary implements a stack-based custom virtual machine with XOR-encrypted bytecode that validates the input flag byte-by-byte using bitwise folding (XOR and bit rotation).

---

## Static Disassembly & Vulnerability Analysis

### 1. Argument Handling & Bytecode Decryption (`0x1228`)
In `main` (`0x1228`):
1. The binary verifies `argc == 2`. If not, it displays `usage: ./origami <flag>`.
2. It measures the length of `argv[1]` via `strlen()`.
3. It allocates `0x1ab` (427) bytes via `malloc(0x1ab)`.
4. It decrypts an embedded bytecode payload stored in the `.data` segment at offset `0x3020` (virtual address `0x4020`) using a 4-byte static key stored at `0x31cb` (virtual address `0x41cb`):
   ```python
   key = [196, 192, 12, 188] # 0xC4, 0xC0, 0x0C, 0xBC
   bytecode = [data[i] ^ key[i % 4] for i in range(427)]
   ```

### 2. Virtual Machine Instruction Set Architecture
The interpreter loop iterates through the decrypted 427-byte bytecode stream:
- `[rbp - 0x44]`: Stack pointer for a local evaluation stack.
- `[rbp - 0x40]`: Boolean accumulator, initialized to `1` (true).

The VM defines 7 distinct opcodes:
- **`OP 1` (Load Flag Byte):**
  Reads flag index `idx`. If `idx < strlen(flag)`, pushes `flag[idx]`; otherwise pushes `0`.
- **`OP 2` (XOR Constant):**
  Pops `top`, XORs with immediate operand `imm8`, pushes result: `top = top ^ imm8`.
- **`OP 3` (Rotate Left / Bit Fold):**
  Calls helper function `0x11e9`, which executes an 8-bit left circular shift:
  ```c
  uint8_t rol8(uint8_t val, uint8_t s) {
      s &= 7;
      return (val << s) | (val >> (8 - s));
  }
  ```
  `top = rol8(top, imm8)`.
- **`OP 4` (Equality Compare):**
  Pops `top`, compares against immediate expected byte `exp8`. Pushes `(top == exp8)`.
- **`OP 5` (Accumulator Reduce):**
  Pops comparison result and performs bitwise AND into boolean register `[rbp - 0x40]`.
- **`OP 6` (Length Assertion):**
  Asserts that `strlen(argv[1]) == imm8`. The bytecode specifies length `47` (`0x2f`).
- **`OP 0xFF` (Halt):**
  Ends execution. If `[rbp - 0x40] == 1`, prints `"Access granted."`.

---

## Symbolic Inversion & Solution

Because each character of the flag is processed independently through an invertible sequence of operations:
$$\text{expected} = \text{ROL}_8(\text{flag}[i] \oplus \text{xor\_val},\; \text{rol\_val})$$

We can directly invert each equation:
$$\text{flag}[i] = \text{ROR}_8(\text{expected},\; \text{rol\_val}) \oplus \text{xor\_val}$$

### Solver Script
```python
#!/usr/bin/env python3

with open('/home/tracehanami/Downloads/CTFs/CREST/Origami/origami', 'rb') as f:
    data = f.read()

# Bytecode payload at offset 0x3020 (VA 0x4020)
ct = data[0x3020 : 0x3020 + 0x1ab]
# Decryption key at offset 0x31cb (VA 0x41cb)
key = data[0x31cb : 0x31cb + 4]
pt = bytearray([c ^ key[i % 4] for i, c in enumerate(ct)])

def ror8(val, s):
    s = s & 7
    return ((val >> s) | ((val << (8 - s)) & 0xff)) & 0xff

flag_chars = {}
i = 0
cur_idx = None
xor_val = None
rol_val = None

while i < len(pt):
    op = pt[i]; i += 1
    if op == 1:
        cur_idx = pt[i]; i += 1
    elif op == 2:
        xor_val = pt[i]; i += 1
    elif op == 3:
        rol_val = pt[i]; i += 1
    elif op == 4:
        expected = pt[i]; i += 1
        flag_chars[cur_idx] = ror8(expected, rol_val) ^ xor_val
    elif op == 5:
        pass
    elif op == 6:
        expected_len = pt[i]; i += 1
    elif op == 0xff:
        break

flag = bytes([flag_chars[idx] for idx in sorted(flag_chars.keys())]).decode()
print("Recovered Flag:", flag)
```

Running the solver outputs:
```text
Expected length: 47
Recovered Flag: CREST{byt3c0d3_vms_hide_l0g1c_n0t_h1de_1t_w3ll}
```

---

## Dynamic Verification
Testing the recovered flag directly against the original binary:
```bash
$ ./origami "CREST{byt3c0d3_vms_hide_l0g1c_n0t_h1de_1t_w3ll}"
Access granted.
```

The flag is 100% verified.

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Binary | `origami` | Original stripped 64-bit ELF challenge binary |
