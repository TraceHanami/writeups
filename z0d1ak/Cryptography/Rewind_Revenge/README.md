# Writeup: Rewind Revenge (Cryptography)

## Challenge Description
- **Target**: `rewind-revenge-a8e91792908f.chals.z0d1ak.org:1337` (SSL)
- **Goal**: Forge a valid ciphertext and authentication tag for the privileged command `print_the_flag!!`.
- **Vulnerability**: Nonce reuse in AES-GCM (Joux's Attack).

---

## Analysis

When connecting to the service, the following interface is presented:
```text
The maintainer rewinds the same AES-GCM nonce every time a command is sealed.
All commands are exactly 16 bytes long; privileged commands cannot be sealed.
Forge a valid sealed `print_the_flag!!` command.

[1] Seal a non-privileged 16-byte command (hex)
[2] Submit a sealed command
[3] Exit
```

### AES-GCM Mechanics
AES-GCM combines CTR mode encryption with the polynomial evaluation authentication mechanism **GHASH** over the finite field $\text{GF}(2^{128})$ defined modulo the irreducible polynomial:
$$f(x) = x^{128} + x^7 + x^2 + x + 1$$

For a 1-block message (16 bytes) with ciphertext block $C$ and length block $L$:
1. **Keystream**:
   $$C = P \oplus E_K(J_1)$$
   where $J_1 = \text{incr}(J_0)$.
2. **GHASH**:
   $$\text{GHASH}_H(C) = C \cdot H^2 \oplus L \cdot H$$
   where $H = E_K(0^{128})$ is the hash subkey in $\text{GF}(2^{128})$.
3. **Authentication Tag**:
   $$T = \text{GHASH}_H(C) \oplus E_K(J_0) = (C \cdot H^2 \oplus L \cdot H) \oplus \text{Mask}$$
   where $\text{Mask} = E_K(J_0)$.

---

## Nonce-Reuse Exploitation

Because the server encrypts all messages using the exact same key and nonce:

### 1. Keystream Recovery
Query option `[1]` with known plaintext $P_1$ to receive $(C_1, T_1)$:
$$E_K(J_1) = P_1 \oplus C_1$$

### 2. Hash Subkey ($H$) Recovery
Query option `[1]` with a second known plaintext $P_2$ to receive $(C_2, T_2)$:
$$T_1 \oplus T_2 = (C_1 \oplus C_2) \cdot H^2$$
$$H^2 = (T_1 \oplus T_2) \cdot (C_1 \oplus C_2)^{-1} \pmod{f(x)}$$

In $\text{GF}(2^{128})$, the Frobenius automorphism implies $a^2$ is an automorphism, so:
$$H = (H^2)^{2^{127}}$$

### 3. Mask Recovery & Forgery
With $H$ known:
$$\text{Mask} = T_1 \oplus (C_1 \cdot H^2) \oplus (L \cdot H)$$

For the target privileged command $P^* = \text{"print\_the\_flag!!"}$:
1. Compute the forged ciphertext:
   $$C^* = P^* \oplus E_K(J_1)$$
2. Compute the valid authentication tag:
   $$T^* = (C^* \cdot H^2 \oplus L \cdot H) \oplus \text{Mask}$$

Submitting $(C^*, T^*)$ to option `[2]` verifies authentication and executes the command.

---

## Exploit Script

```python
from pwn import *

def gmul(a, b):
    V = a
    Z = 0
    for i in range(128):
        bit = (b >> (127 - i)) & 1
        if bit:
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ (0xe1 << 120)
        else:
            V >>= 1
    return Z

def gpow(a, exp):
    res = int.from_bytes(bytes.fromhex('80000000000000000000000000000000'), 'big')
    base = a
    while exp > 0:
        if exp & 1:
            res = gmul(res, base)
        base = gmul(base, base)
        exp >>= 1
    return res

def ginv(a):
    return gpow(a, (1 << 128) - 2)

def gsqrt(a):
    return gpow(a, 1 << 127)

def seal(r, pt_hex):
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'> ')
    r.sendline(pt_hex.encode())
    
    line1 = r.recvline().decode()
    line2 = r.recvline().decode()
    
    ct_hex = line1.split('=')[1].strip()
    tag_hex = line2.split('=')[1].strip()
    
    return bytes.fromhex(ct_hex), bytes.fromhex(tag_hex)

def submit(r, ct_hex, tag_hex):
    r.recvuntil(b'> ')
    r.sendline(b'2')
    r.recvuntil(b'> ')
    r.sendline(ct_hex.encode())
    r.recvuntil(b'> ')
    r.sendline(tag_hex.encode())
    return r.recvall(timeout=5).decode(errors='ignore')

def main():
    r = remote('rewind-revenge-a8e91792908f.chals.z0d1ak.org', 1337, ssl=True)
    
    p1 = b'A' * 16
    p2 = b'B' * 16
    
    ct1, tag1 = seal(r, p1.hex())
    ct2, tag2 = seal(r, p2.hex())
    
    keystream = bytes([a ^ b for a, b in zip(p1, ct1)])
    
    C1 = int.from_bytes(ct1, 'big')
    T1 = int.from_bytes(tag1, 'big')
    C2 = int.from_bytes(ct2, 'big')
    T2 = int.from_bytes(tag2, 'big')
    
    delta_T = T1 ^ T2
    delta_C = C1 ^ C2
    
    H2 = gmul(delta_T, ginv(delta_C))
    H = gsqrt(H2)
    
    L = int.from_bytes(bytes.fromhex('00000000000000000000000000000080'), 'big')
    Mask = T1 ^ gmul(C1, H2) ^ gmul(L, H)
    
    target_pt = b'print_the_flag!!'
    target_ct = bytes([a ^ b for a, b in zip(target_pt, keystream)])
    
    C_target = int.from_bytes(target_ct, 'big')
    T_target = Mask ^ gmul(C_target, H2) ^ gmul(L, H)
    target_tag = T_target.to_bytes(16, 'big')
    
    res = submit(r, target_ct.hex(), target_tag.hex())
    print(res)

if __name__ == '__main__':
    main()
```

---

## Flag
```
zdk{10cAL_REwInD_Rev3ng3_FL4G}
```
