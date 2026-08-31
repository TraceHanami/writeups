# ASIS CTF - LeakMeAk Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Binary:** [`leakmeak.elf`](file:///home/tracehanami/Downloads/Asis/LeakMeAk/leakmeak.elf)
- **Architecture:** x86-64 ELF (PIE, dynamically linked, stripped)

---

## 1. Initial Analysis & Triage

Checking file properties and metadata:
```bash
$ file leakmeak.elf
leakmeak.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped
```

Running strings and decompiling the entry point reveals:
- Prompt: `"Enter Flag: "`
- Input format specifier: `"%127s"`
- String length check: `strlen(input) == 0x22` (34 bytes)
- Prefix check: `strncmp(input, "ASIS{", 5) == 0`
- Suffix check: `input[33] == '}'`

The flag payload is therefore 28 characters inside `ASIS{...}`.

---

## 2. Reverse Engineering the Verification Logic

### 2.1 State Initialization
The binary initializes an 8-byte state array on the stack at `rsp + 0x30`:
```c
uint8_t state_30[8] = { 0x05, 0x15, 0x0a, 0x0e, 0x00, 0x00, 0x00, 0x00 };
uint8_t state_38[8] = { 0 };
```

### 2.2 Processing 4-Byte Blocks
The 28-byte payload is split into 7 chunks of 4 bytes: `(b0, b1, b2, b3)`.
For each chunk $k \in [0, 6]$:
1. Lookup elements in `state_30` using indices extracted from `b2 & 7` and `b3 & 7`.
2. Compute temporary register `r11d` based on `b0 & 3` and state variables.
3. Compute `v[k]` (a 32-bit integer) via:
   $$\text{edx} = (b_0 \ll 24) \mid (b_1 \ll 16) \mid (b_2 \ll 8) \mid b_3$$
   $$\text{esi} = (r_{11} \ll 24) \oplus (\text{state}_{30}[b_2 \ \& \ 7] \ll 16) \oplus (\text{state}_{30}[b_3 \ \& \ 7] \ll 8) \oplus (b_1 \ \& \ 7)$$
   $$v[k] = (\text{edx} \times \mathtt{0x9e3779b9}) \oplus \text{esi} \pmod{2^{32}}$$
4. Update state:
   $$\text{state}_{30}[b_1 \ \& \ 7] = r_{11} \ \& \ \mathtt{0xff}$$
   $$\text{state}_{38}[b_1 \ \& \ 7] = 0$$

### 2.3 Cyclic Constraints Verification
Once all 7 values $v[0 \dots 6]$ are generated, they are validated against two hardcoded 32-bit constant arrays `table1` and `table2`:

```c
const uint32_t table1[8] = {0x00000000, 0x449f4ab5, 0xbb5e7ac4, 0x91141f33, 0x9caafb86, 0xd99258f7, 0x2abb0f38, 0x3ff226d0};
const uint32_t table2[8] = {0x00000000, 0xa5a5a5a5, 0x5a5a5a5a, 0x3c3c3c3c, 0xc3c3c3c3, 0x96969696, 0x69696969, 0x1f1f1f1f};
```

For $i \in [1, 7]$:
$$\left( \text{ror32}(v[i \pmod 7], 13) + v[i-1] \right) \oplus \text{table2}[i] == \text{table1}[i]$$

Let $\text{Target}[i] = \text{table1}[i] \oplus \text{table2}[i]$. This gives a cyclic system of linear equations with right rotations over $\mathbb{Z}_{2^{32}}$.

Additionally:
- A hash of $v[0 \dots 6]$ is verified:
  ```python
  edx = 0
  for i in range(7):
      edx = ((edx * 33) ^ v[i]) & 0xFFFFFFFF
  assert edx == 0xddaacf25
  ```
- Final state assertions:
  $$\text{state}_{30}[0] \ \& \ 3 == 1$$
  $$\text{state}_{30}[1] \ \& \ 3 == 2$$

---

## 3. Solution Strategy

We use **Z3 SMT Solver** in Python to solve this in two stages:
1. **Stage 1:** Recover the 7 vector values $v[0 \dots 6]$.
2. **Stage 2:** Symbolically model the block processing and state transitions to recover the 28 printable ASCII characters of the flag.

### Solve Script (`solver.py`)
```python
import z3

# -----------------------------
# Stage 1: Solve for vector v
# -----------------------------
t1 = [0x00000000, 0x449f4ab5, 0xbb5e7ac4, 0x91141f33, 0x9caafb86, 0xd99258f7, 0x2abb0f38, 0x3ff226d0]
t2 = [0x00000000, 0xa5a5a5a5, 0x5a5a5a5a, 0x3c3c3c3c, 0xc3c3c3c3, 0x96969696, 0x69696969, 0x1f1f1f1f]
target = [t1[i] ^ t2[i] for i in range(8)]

s1 = z3.Solver()
v = [z3.BitVec(f'v_{i}', 32) for i in range(7)]

for i in range(1, 8):
    s1.add(z3.RotateRight(v[i % 7], 13) + v[i - 1] == target[i])

edx = z3.BitVecVal(0, 32)
for i in range(7):
    edx = (edx * 33) ^ v[i]
s1.add(edx == 0xddaacf25)

assert s1.check() == z3.sat
m1 = s1.model()
target_v = [m1[v[i]].as_long() for i in range(7)]
print("Recovered v:", [hex(x) for x in target_v])

# -----------------------------
# Stage 2: Solve for flag bytes
# -----------------------------
s2 = z3.Solver()
flag = [z3.BitVec(f'c_{i}', 8) for i in range(28)]

for i in range(28):
    s2.add(flag[i] >= 0x20, flag[i] <= 0x7e)

st_30 = [z3.BitVecVal(x, 8) for x in [0x05, 0x15, 0x0a, 0x0e, 0x00, 0x00, 0x00, 0x00]]

def select_byte(arr, idx_bv):
    res = arr[0]
    for i in range(1, 8):
        res = z3.If(idx_bv == i, arr[i], res)
    return res

def update_byte(arr, idx_bv, val):
    return [z3.If(idx_bv == i, val, arr[i]) for i in range(8)]

for k in range(7):
    b0 = z3.ZeroExt(24, flag[4*k])
    b1 = z3.ZeroExt(24, flag[4*k + 1])
    b2 = z3.ZeroExt(24, flag[4*k + 2])
    b3 = z3.ZeroExt(24, flag[4*k + 3])

    r15 = b0 & 3
    ebx = b1 & 7
    rsi_idx = b2 & 7
    rdi_idx = b3 & 7
    
    esi_val = z3.ZeroExt(24, select_byte(st_30, rsi_idx))
    edi_val = z3.ZeroExt(24, select_byte(st_30, rdi_idx))
    
    bpl_val = edi_val & 3
    r11_case_0_not1 = z3.If(bpl_val == 1, edi_val, z3.BitVecVal(0, 32))
    r11_case_0 = z3.If((esi_val & 3) == 1, esi_val, r11_case_0_not1)
    
    r11_final = z3.If(r15 == 0, r11_case_0,
                      z3.If(r15 == 1, esi_val, ((b0 << 4) & 0x10) | 5))
    
    st_30 = update_byte(st_30, ebx, z3.Extract(7, 0, r11_final))
    
    edx_in = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    esi_in = ((r11_final & 0xff) << 24) ^ ((esi_val & 0xff) << 16) ^ ((edi_val & 0xff) << 8) ^ (ebx & 0xff)
    v_k = (edx_in * 0x9e3779b9) ^ esi_in
    
    s2.add(v_k == target_v[k])

s2.add((st_30[0] & 3) == 1)
s2.add((st_30[1] & 3) == 2)

if s2.check() == z3.sat:
    m2 = s2.model()
    sol_bytes = bytes([m2[flag[i]].as_long() for i in range(28)])
    full_flag = b"ASIS{" + sol_bytes + b"}"
    print("[+] Flag Found:", full_flag.decode())
```

---

## 4. Execution & Validation

```bash
$ python3 solver.py
Recovered v: ['0xcf6a545', '0x89397a88', '0x54c2caf9', '0xab02cb0c', '0xcda7368c', '0xb2fab02b', '0xf6c4d21a']
[+] Flag Found: ASIS{haaducrcplmekhylrozcxyxzuizs}

$ echo "ASIS{haaducrcplmekhylrozcxyxzuizs}" | ./leakmeak.elf
Enter Flag: Access Granted! Correct Flag.
```

---

## Flag
```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```
