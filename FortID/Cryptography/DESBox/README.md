# FortID CTF — DESBox

**Category:** Cryptography  
**CTF Event:** FortID CTF  
**Artifacts:**
- `DESBox.py` (4,977 bytes)
- `solve.py` (3,644 bytes)  
**Status:** Solved  
**Attack Vector:** DES Complementation Property & Deterministic Permutation Bypass  

---

## 1. Challenge Overview

In DESBox, an interactive encryption service encrypts the secret `FLAG` under a 24-byte 3DES key derived from user input:
```python
def load_key(user_key):
    return permute(user_key)
```
The server challenges the participant to decrypt a target ciphertext while applying strict key checks and random byte shuffling.

---

## 2. Mathematical Vulnerability Analysis

### A. Permutation Elimination via Uniform Key Vector
`load_key(user_key)` applies a pseudorandom permutation over the 24 bytes of `user_key`.  
If we supply a uniform key where all 24 bytes are identical:
$$\text{user\_key} = [v, v, v, \dots, v] \implies \text{permute}(\text{user\_key}) = [v, v, v, \dots, v]$$
The output is completely invariant under any permutation, eliminating random key shuffling entirely.

### B. DES Complementation Property
The Data Encryption Standard (DES) and Triple-DES (3DES) adhere to the fundamental complementation property:
$$\text{DES}_K(P) = C \iff \text{DES}_{\sim K}(\sim P) = \sim C$$
$$\text{DES3}_K(P) = C \iff \text{DES3}_{\sim K}(\sim P) = \sim C$$
where $\sim X$ denotes the bitwise NOT operation ($X \oplus \text{0xFF}$).

### C. Validation Bypass & Flag Extraction
1. Query the oracle to encrypt the unknown flag under Key $A = \text{0x00} \times 24$:
   $$C_1 = \text{DES3}_A(\text{FLAG})$$
2. Request the decryption of bitwise inverted ciphertext $\sim C_1$ under the complemented key $\sim A = \text{0xFF} \times 24$:
   $$P_{\text{rec}} = \text{DES3}^{-1}_{\sim A}(\sim C_1)$$
3. By the complementation theorem:
   $$\text{DES3}^{-1}_{\sim A}(\sim C_1) = \sim \text{DES3}^{-1}_A(C_1) = \sim \text{FLAG}$$
4. Inverting $P_{\text{rec}}$ yields the original unpadded flag plaintext:
   $$\text{FLAG} = \sim P_{\text{rec}}$$

---

## 3. Exploit Script (`solve.py`)

```python
from pwn import *

def bitwise_not(b):
    return bytes([x ^ 0xFF for x in b])

io = remote('target_host', 1337)

# Key 1: Uniform null bytes (0x00 * 24)
key_a = bytes([0x00] * 24)
# Key 2: Bitwise complement (0xFF * 24)
key_comp = bitwise_not(key_a)

# Step 1: Encrypt flag under key_a
io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Key: ', key_a.hex().encode())
c1 = bytes.fromhex(io.recvline().strip().decode())

# Step 2: Decrypt ~c1 under ~key_a
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Key: ', key_comp.hex().encode())
io.sendlineafter(b'Ciphertext: ', bitwise_not(c1).hex().encode())
p_inverted = bytes.fromhex(io.recvline().strip().decode())

# Step 3: Recover flag
flag = bitwise_not(p_inverted)
print(f"[+] Recovered Flag: {flag.decode()}")
```
