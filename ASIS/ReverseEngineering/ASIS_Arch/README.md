# ASIS CTF — ASIS-Arch Challenge Writeup

## 1. Challenge Overview
| Property | Details |
| :--- | :--- |
| **Category** | Reverse Engineering / Cryptography |
| **Challenge Files** | `qemu-asisarch` (Custom VM Emulator ELF), `challenge.rom` (ROM image) |
| **Architecture** | Custom 16-bit RISC VM (`ASIS-Arch`) with 8 registers (`r0`–`r7`), 64 KB memory, and instruction encryption |
| **Flag** | `ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}` |

---

## 2. Architecture & Virtual Machine Reversing

### Memory and Registers
- **Memory**: 64 KB flat address space.
  - `0x0000`–`0x7C50`: Code Section
  - `0x7C50`–`0x7D80`: String & Verification Data
  - `0xC000`–`0xC02B`: RAM buffer holding the 44-byte flag as 22 little-endian 16-bit words ($w[0..21]$)
- **Registers**: 8 general-purpose 16-bit registers: `r0`, `r1`, `r2`, `r3`, `r4`, `r5`, `r6`, `r7`, plus `PC` and `SP`.

---

### Instruction De-obfuscation
Each instruction is 4 bytes long and encrypted based on its `PC`. The emulator decodes each instruction using the following steps:

#### 1. Key Derivation & Byte Permutation
```python
k = (((pc ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff)
rot_k = ((k << 5) | (k >> 11)) & 0xffff
t = (k >> 14) & 3

# Permutation matrix table located at 0x2140 in ELF:
PERM_TABLE = [
    [0, 1, 2, 3],
    [2, 0, 3, 1],
    [3, 2, 1, 0],
    [1, 3, 0, 2]
]
p = PERM_TABLE[t]

b0 = mem[pc + p[0]]
b1 = mem[pc + p[1]]
b2 = mem[pc + p[2]]
b3 = mem[pc + p[3]]
```

#### 2. Opcode Extraction
```python
al = (((0x5d * pc) ^ rot_k ^ b2) & 0xff)
shift = (rot_k >> 5) & 7
opcode = (((al << shift) | (al >> (8 - shift))) & 0xff) ^ 0x6d
```

#### 3. Register & Operand Extraction
The destination register (`rd`) and source register (`rs`) indices use the permutation involution $g(x) = ((5x) \oplus 3) \pmod 8$:
```python
r8d = b1 ^ (rot_k & 0xff)
r8b = (((r8d << 4) | (r8d >> 4)) & 0xff)
ecx = (rot_k >> 2) & 0xffff
eax = (((pc * 7) ^ ecx ^ b0 ^ r8b) & 0xff)
eax = ((eax * 5) ^ 3) & 7
rd = ((eax * 5) ^ 3) & 7  # Destination register

dl = (b3 ^ ((rot_k >> 8) & 0xff)) & 0xff
dl = (((dl << 4) | (dl >> 4))) & 0xff
dx = ((dl << 8) | r8b) & 0xffff
dx = ((dx << 5) | (dx >> 11)) & 0xffff
rs = ((dx & 7) * 5 ^ 3) & 7 # Source register base
offset = dx >> 3            # Memory offset
```

---

### Opcode Set
From the jump table at `.data.rel.ro` (offset `0x25e0` in the ELF binary):

| Opcode | Mnemonic | Operation |
| :--- | :--- | :--- |
| `0x15` | `MOV_IMM rd, imm` | `regs[rd] = imm` |
| `0x21` | `ADD_IMM rd, imm` | `regs[rd] = (regs[rd] + imm) & 0xffff` |
| `0x27` | `SUB_IMM rd, imm` | `regs[rd] = (regs[rd] - imm) & 0xffff` |
| `0x32` | `XOR_IMM rd, imm` | `regs[rd] ^= imm` |
| `0x38` | `AND_IMM rd, imm` | `regs[rd] &= imm` |
| `0x44` | `ROL_IMM rd, n` | `regs[rd] = rol16(regs[rd], n)` |
| `0x4B` | `MOV_REG rd, rs` | `regs[rd] = regs[rs]` |
| `0x50` | `ADD_REG rd, rs` | `regs[rd] = (regs[rd] + regs[rs]) & 0xffff` |
| `0x56` | `SUB_REG rd, rs` | `regs[rd] = (regs[rd] - regs[rs]) & 0xffff` |
| `0x5C` | `XOR_REG rd, rs` | `regs[rd] ^= regs[rs]` |
| `0x63` | `LDB rd, [rs+off]` | `regs[rd] = mem[regs[rs] + off]` |
| `0x69` | `STB [rs+off], rd` | `mem[regs[rs] + off] = regs[rd] & 0xff` |
| `0x71` | `LDW rd, [rs+off]` | `regs[rd] = mem16[regs[rs] + off]` |
| `0x77` | `STW [rs+off], rd` | `mem16[regs[rs] + off] = regs[rd]` |
| `0x80` | `JMP target` | `pc = target` |
| `0x86` | `JNE rd, target` | `if regs[rd] == 0: pc = target` |
| `0x8C` | `JE rd, target` | `if regs[rd] != 0: pc = target` |
| `0x92` | `PUSH rd` | Push `regs[rd]` to stack |
| `0x98` | `POP rd` | Pop to `regs[rd]` |
| `0xA1` | `CALL target` | Push return address, `pc = target` |
| `0xA7` | `RET` | Pop `pc` from stack |
| `0xB3` | `GETC rd` | Read byte from `stdin` |
| `0xB9` | `PUTC rd` | Write byte to `stdout` |
| `0xC2` | `SUB_SBOX rd` | `regs[rd] = (SBOX[hi] << 8) | SBOX[lo]` |
| `0xFE` | `HLT` | Halt VM |

---

## 3. Disassembly & Cipher Structure

### Input Stage (`0x0000`–`0x0024`)
1. Prints banner and prompt `"Enter flag: "`.
2. Reads 44 characters into `0xC000..0xC02B`.
3. Verifies length == 44 bytes.

---

### 10 Rounds of Custom Block Cipher (`0x0024`–`0x7874`)
The transformation consists of **7,700 straight-line instructions**, organized into **10 rounds of 770 instructions each**.

Each round $r \in [0, 9]$ transforms the 22 words $w[0..21]$ via:

#### 1. S-Box Substitution & Round Key Addition (132 instructions)
For each $i \in [0, 21]$:
$$w[i] \leftarrow \text{SBox}_{16}(w[i]) \oplus K_{r, i}$$

#### 2. ARX Linear Diffusion Layer (638 instructions)
- **Phase A (Additive Ring Mixing)**:
  $$\text{For } i = 0 \dots 21: \quad w[i] \leftarrow (w[i] + w[(i - 1) \pmod{22}] + \text{0x5A5A}) \pmod{2^{16}}$$

- **Phase B (Linear Rotation & Diffusion)**:
  Define $f(x) = x \oplus \text{ROL}_{16}(x, 5) \oplus \text{ROL}_{16}(x, 11)$.
  $$\text{For } i = 0 \dots 21: \quad w[i] \leftarrow w[i] \oplus f(w[(i + 1) \pmod{22}]) \oplus \text{ROL}_{16}(f(w[(i + 2) \pmod{22}]), r + 1)$$

---

### 4. Verification Check Block (`0x7874`–`0x7BE8`)
At the end of Round 9, the final state is checked against 22 expected 16-bit words extracted from the ROM table at offset `0x7CDB`:

| Word Address | Expected Word Value |
| :---: | :---: |
| `0xC000` | `0x544C` |
| `0xC002` | `0x15A0` |
| `0xC004` | `0xEB44` |
| `0xC006` | `0x09D6` |
| `0xC008` | `0xB6AB` |
| `0xC00A` | `0x496E` |
| `0xC00C` | `0xFD0A` |
| `0xC00E` | `0x3806` |
| `0xC010` | `0xF1DF` |
| `0xC012` | `0x0913` |
| `0xC014` | `0xFFD8` |
| `0xC016` | `0x8549` |
| `0xC018` | `0xDEBB` |
| `0xC01A` | `0x5400` |
| `0xC01C` | `0x261A` |
| `0xC01E` | `0x5185` |
| `0xC020` | `0xA205` |
| `0xC022` | `0xA0B8` |
| `0xC024` | `0xBE18` |
| `0xC026` | `0xEFFF` |
| `0xC028` | `0xB9B9` |
| `0xC02A` | `0xE889` |

---

## 5. Solution & Inversion

Since all operations are bijective and unbranched, we can invert the cipher deterministically round-by-round from $r = 9$ down to $0$:

1. **Invert Phase B**: Run $i = 21$ down to $0$:
   $$w[i] \leftarrow w[i] \oplus f(w[(i+1) \pmod{22}]) \oplus \text{ROL}_{16}(f(w[(i+2) \pmod{22}]), r + 1)$$

2. **Invert Phase A**: Run $i = 21$ down to $0$:
   $$w[i] \leftarrow (w[i] - w[(i-1) \pmod{22}] - \text{0x5A5A}) \pmod{2^{16}}$$

3. **Invert Phase 1**:
   $$w[i] \leftarrow \text{InvSBox}_{16}(w[i] \oplus K_{r, i})$$

---

## 6. Complete Python Solver Script (`solve_perfect.py`)

```python
#!/usr/bin/env python3
import sys

with open('challenge.rom', 'rb') as f:
    rom = f.read()

payload = rom[0x20:]

PERM_TABLE = [
    [0, 1, 2, 3],
    [2, 0, 3, 1],
    [3, 2, 1, 0],
    [1, 3, 0, 2]
]

SBOX = [
    0xfc, 0x9e, 0x7b, 0x6e, 0xce, 0x09, 0x97, 0x5b, 0x5f, 0xbf, 0x78, 0xbb, 0x79, 0xe6, 0x64, 0xea,
    0x99, 0x8d, 0x48, 0xd9, 0x4d, 0x69, 0x0d, 0xa4, 0xef, 0x5a, 0xcb, 0x81, 0x8b, 0xb0, 0x4a, 0x43,
    0xde, 0xd3, 0xd1, 0xa8, 0x0e, 0xbc, 0xe0, 0xd8, 0xb5, 0x01, 0xb6, 0xfe, 0x3b, 0x8c, 0x86, 0x25,
    0x1b, 0x57, 0x4c, 0x7d, 0xd7, 0x0a, 0x82, 0xab, 0x0b, 0x07, 0x1f, 0x00, 0x13, 0xb9, 0x8e, 0x17,
    0xa6, 0x5d, 0xc0, 0xca, 0x8f, 0xae, 0x6c, 0x83, 0x3c, 0xf3, 0x2d, 0xdf, 0x44, 0x89, 0xee, 0xe1,
    0x7e, 0x03, 0x39, 0x85, 0xe3, 0xd4, 0x2c, 0x40, 0xd6, 0x87, 0xac, 0x93, 0x4f, 0xf9, 0x3f, 0x31,
    0xc2, 0x45, 0x16, 0xb7, 0x24, 0xb3, 0x36, 0x30, 0x7c, 0x91, 0x2f, 0xad, 0xcd, 0x27, 0x5c, 0x80,
    0xaa, 0xcf, 0x2e, 0x47, 0x53, 0xf8, 0x55, 0x9f, 0x50, 0x66, 0x75, 0xff, 0x26, 0xdc, 0x67, 0x12,
    0x88, 0x96, 0x10, 0x2a, 0xd2, 0x74, 0x19, 0x06, 0x4b, 0x11, 0x9b, 0xb4, 0x32, 0xd5, 0xf1, 0xa9,
    0xd0, 0x1e, 0xbe, 0xaf, 0x98, 0x05, 0xed, 0xe9, 0x46, 0x76, 0x9c, 0x4e, 0x58, 0x20, 0x35, 0x7a,
    0xc4, 0x68, 0x3a, 0x92, 0x77, 0xa7, 0xa2, 0x22, 0x33, 0xa0, 0x1c, 0xfd, 0xec, 0xf4, 0x5e, 0x56,
    0x02, 0x41, 0xb8, 0xdb, 0x65, 0x0f, 0x18, 0x21, 0x6f, 0x90, 0xb1, 0x70, 0x38, 0x6b, 0x23, 0xeb,
    0x51, 0x73, 0x3d, 0xe5, 0xc7, 0x6a, 0xcc, 0x28, 0xf5, 0x71, 0xf0, 0xdd, 0x3e, 0x14, 0xc3, 0x9a,
    0xfb, 0x95, 0xe7, 0x62, 0x54, 0xa3, 0xb2, 0x29, 0xe4, 0x6d, 0x9d, 0x84, 0xf2, 0xe8, 0x15, 0xa5,
    0x2b, 0xc5, 0x1d, 0x49, 0x61, 0xe2, 0xfa, 0xbd, 0xc9, 0x1a, 0x0c, 0x42, 0x8a, 0x72, 0x34, 0x7f,
    0x08, 0x63, 0x94, 0xa1, 0xf7, 0xf6, 0x37, 0xc1, 0x59, 0x52, 0xc6, 0x04, 0xc8, 0xba, 0x60, 0xda
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

def inv_sbox16(w):
    return (INV_SBOX[(w >> 8) & 0xff] << 8) | INV_SBOX[w & 0xff]

def rol16(val, r):
    return ((val << r) | (val >> (16 - r))) & 0xffff

def f_linear(w):
    return w ^ rol16(w, 5) ^ rol16(w, 11)

def decode(mem, pc):
    k = (((pc ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff)
    rot_k = ((k << 5) | (k >> 11)) & 0xffff
    t = (k >> 14) & 3
    p = PERM_TABLE[t]
    
    b0, b1, b2, b3 = mem[pc + p[0]], mem[pc + p[1]], mem[pc + p[2]], mem[pc + p[3]]
    
    al = (((0x5d * pc) ^ rot_k ^ b2) & 0xff)
    shift = (rot_k >> 5) & 7
    opcode = (((al << shift) | (al >> (8 - shift))) & 0xff) ^ 0x6d
    
    r8d = b1 ^ (rot_k & 0xff)
    r8b = (((r8d << 4) | (r8d >> 4)) & 0xff)
    ecx = (rot_k >> 2) & 0xffff
    eax = (((pc * 7) ^ ecx ^ b0 ^ r8b) & 0xff)
    eax = ((eax * 5) ^ 3) & 7
    rd = ((eax * 5) ^ 3) & 7
    
    dl = (b3 ^ ((rot_k >> 8) & 0xff)) & 0xff
    dl = (((dl << 4) | (dl >> 4))) & 0xff
    dx = ((dl << 8) | r8b) & 0xffff
    dx = ((dx << 5) | (dx >> 11)) & 0xffff
    rs = ((dx & 7) * 5 ^ 3) & 7
    offset = dx >> 3
    
    return opcode, rd, dx, rs, offset

# Parse all 10 rounds
insns = []
pc = 0x0024
while pc < 0x7874:
    op, rd, arg, rs, off = decode(payload, pc)
    insns.append((pc, op, rd, arg, rs, off))
    pc += 4

rounds = [insns[i*770 : (i+1)*770] for i in range(10)]

# Target words from verification check
target_words = [
    0x544c, 0x15a0, 0xeb44, 0x09d6, 0xb6ab, 0x496e, 0xfd0a, 0x3806,
    0xf1df, 0x0913, 0xffd8, 0x8549, 0xdebb, 0x5400, 0x261a, 0x5185,
    0xa205, 0xa0b8, 0xbe18, 0xefff, 0xb9b9, 0xe889
]

def invert_round(r_idx, out_w):
    part1 = rounds[r_idx][:132]
    shift_term2 = r_idx + 1
    w = list(out_w)
    
    # 1. Invert Phase B (21 down to 0)
    for i in range(21, -1, -1):
        idx1 = (i + 1) % 22
        idx2 = (i + 2) % 22
        w[i] ^= f_linear(w[idx1]) ^ rol16(f_linear(w[idx2]), shift_term2)
        
    # 2. Invert Phase A (21 down to 0)
    for i in range(21, -1, -1):
        prev_idx = (i - 1) % 22
        w[i] = (w[i] - w[prev_idx] - 0x5a5a) & 0xffff
        
    # 3. Invert SBox + Round Keys
    round_keys = [part1[i*6 + 3][3] for i in range(22)]
    in_w = [inv_sbox16(w[i] ^ round_keys[i]) for i in range(22)]
    return in_w

curr = target_words
for r in range(9, -1, -1):
    curr = invert_round(r, curr)

flag_bytes = bytearray()
for w in curr:
    flag_bytes.extend([w & 0xff, (w >> 8) & 0xff])

flag = flag_bytes.decode('latin1')
print(f"[+] Flag: {flag}")
```

---

## 7. Execution & Verification

```bash
$ python3 solve_perfect.py
[+] Flag: ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}

$ echo "ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}" | ./qemu-asisarch -kernel challenge.rom
=== ASISARCH Secure Enclave v2.0 ===
Enter flag: 
[+] Access Granted! Flag verified.
```
