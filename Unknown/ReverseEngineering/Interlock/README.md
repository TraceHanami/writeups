# Interlock / Cipherlock — Linear Algebra Modulo 256 & SMT Solving

**Category:** Reverse Engineering  
**CTF Event:** Unknown CTF (Consolidated under Unknown)  
**Artifacts:**
- `interlock` (14,472 bytes ELF 64-bit stripped binary)
- `cipherlock` (14,472 bytes ELF 64-bit companion binary)
- `solve_interlock.py` (985 bytes Z3 SMT solver)  
**Status:** Solved  
**Recovered Key:** `UNLOCK-SEQ-7Y2AB`  

---

## 1. Challenge Overview

Participants are provided with two stripped 64-bit ELF binaries, `interlock` and `cipherlock`. When executed, the program prompts for a 16-character unlocking password / key. If the key passes verification, the program proceeds to decrypt an internal payload using AES.

---

## 2. Reverse Engineering & Binary Internals

Disassembly and memory analysis of `interlock` reveals:
1. **Target Vector:** Located in `.rodata` at offset `0x2090` (16 bytes).
2. **Transformation Matrix:** Located in `.rodata` at offset `0x20A0` (256 bytes, representing a $16 \times 16$ matrix $M$).
3. **Validation Algorithm:**
   The program accepts a 16-byte input vector $K = [k_0, k_1, \dots, k_{15}]^T$ and computes a matrix-vector product modulo 256:
   $$V = M \cdot K \pmod{256}$$
   where:
   $$v_i = \left(\sum_{j=0}^{15} M_{i, j} \cdot k_j\right) \bmod 256$$
   The resulting vector $V$ is checked against the target vector $T$.

---

## 3. SMT Formulation & Automated Solution (`solve_interlock.py`)

Because matrix multiplication modulo $256$ is not necessarily invertible over $\mathbb{Z}_{256}$ (as $\det(M)$ may share factors with 2), we model the system of modular linear equations using the **Z3 Theorem Prover**:
- Define 16 8-bit bitvectors: $k_0, \dots, k_{15} \in \text{BitVec}(8)$.
- Express the modular matrix multiplication for each equation $i \in \{0, \dots, 15\}$.
- Constrain the output to equal the target vector $T[i]$.

```python
import z3

def solve():
    with open("./interlock", "rb") as f:
        data = f.read()

    # Target vector at .rodata offset 0x2090 (16 bytes)
    target = data[0x2090:0x2090 + 16]
    # 16x16 matrix at .rodata offset 0x20a0 (256 bytes)
    matrix = [list(data[0x20a0 + i * 16 : 0x20a0 + (i + 1) * 16]) for i in range(16)]

    solver = z3.Solver()
    key = [z3.BitVec(f"k_{i}", 8) for i in range(16)]

    # Matrix multiplication modulo 256
    for i in range(16):
        expr = z3.BitVecVal(0, 8)
        for j in range(16):
            expr = expr + (z3.BitVecVal(matrix[i][j], 8) * key[j])
        solver.add(expr == target[i])

    if solver.check() == z3.sat:
        model = solver.model()
        solution = bytes([model[key[i]].as_long() for i in range(16)])
        print(f"[+] Key found: {solution.decode('latin1')}")
        return solution.decode('latin1')
    else:
        print("[-] No solution found.")
        return None

if __name__ == "__main__":
    solve()
```

### Execution Result:
```text
[+] Key found: UNLOCK-SEQ-7Y2AB
```
The key `UNLOCK-SEQ-7Y2AB` passes validation and unlocks the binary.
