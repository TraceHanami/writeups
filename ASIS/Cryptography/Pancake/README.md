# Pancake — Cryptography Challenge Writeup

## Challenge Overview
- **Files Provided**: [`pancake.py`](file:///home/tracehanami/Downloads/Asis/Pancake/pancake.py), [`challenge.json`](file:///home/tracehanami/Downloads/Asis/Pancake/challenge.json)
- **Category**: Cryptography (Symmetric / AES-GCM / Nonce Reuse / KDF Collision)

---

## 1. Challenge Architecture & Source Code Breakdown

### Data Structures & Parameters
- Block size: 128 bits.
- Drop bits: `DEFAULT_DROP = 32`.
- Nonce bits: `NONCE_BITS = 128 - 32 = 96` bits (12 bytes).
- Format block helper: 
  $$\text{format\_block}(x, \text{sep}) = (x \ll 32) \mid (\text{sep} \land (2^{32} - 1))$$

### Key Generation & Hints
1. A 32-bit random integer `seed = randbits(32)` is generated.
2. Two SHA-256 hashes are computed from `seed`:
   - $k_1 = \text{SHA256}(\texttt{"K1-SEED"} \parallel \text{seed})$
   - $\text{hint } a = \text{SHA256}(\texttt{"K1-SEED-HINT"} \parallel \text{seed})$
3. A random 32-byte secret key $k_2$ is generated along with two 96-bit nonces $n_1, n_2$.

### The Collision Search
The script finds an alternate nonce $\text{alt} \neq n_2$ such that:
$$\text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(n_2, 0))) = \text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(\text{alt}, 0)))$$
where $\text{extract\_upper}(X) = X \gg 32$ (the upper 96 bits).

### State Diffusion & Key Derivation
State diffusion is computed as:
- $j = \text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(n_2, 0)))$
- $w_1 = n_1 \oplus j$
- $w_2 = n_1 \oplus \text{GF-Double}(j)$
- $r_1 = \text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(w_1, 0\text{x}18)))$
- $r_2 = \text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(w_2, 0\text{x}28)))$

State vector:
$$\text{state} = (j, w_1, w_2, r_1, r_2)$$

The encryption key $ek$, IV $iv$, and context key $ck$ are derived via `SHAKE-256`:
$$(ek, iv, ck) = \text{SHAKE256}(\texttt{"KDF-STATE-v1"} \parallel k_2 \parallel n_1 \parallel j \parallel w_1 \parallel w_2 \parallel r_1 \parallel r_2)$$

### Encryptions
- **Flag ciphertext ($y$)**: Encrypted with AES-GCM under $(k_1, k_2, n_1, n_2, ad, \text{flag})$.
- **Sample ($x$)**: Known plaintext $m = 0^{128}$ (128 null bytes) encrypted under $(k_1, k_2, n_1, \text{alt}, ad, m)$.
- **Ticket ($z$)**: Encrypted and authenticated record containing $\{n_1, \text{alt}, x\}$ sealed with key:
  $$K_{\text{seal}} = \text{SHA256}(\texttt{"SEALED-TICKET-KEY"} \parallel k_1 \parallel n_1 \parallel \text{alt})[0:16]$$
  $$IV_{\text{seal}} = \text{SHA256}(\texttt{"SEALED-TICKET-IV"} \parallel K_{\text{seal}})[0:12]$$

---

## 2. Vulnerability Analysis

### Flaw 1: 32-bit Seed Space
The seed is only 32 bits ($2^{32} \approx 4.29 \times 10^9$ possibilities). Because $a = \text{SHA256}(\texttt{"K1-SEED-HINT"} \parallel \text{seed})$ is given publicly in `challenge.json`, we can perform an exhaustive search in parallel across 32 bits to recover `seed` and reconstruct $k_1$.

### Flaw 2: State Invariance Under Nonce Collisions
Notice the dependence on $n_2$ during `diffuse_state(k1, n1, n2)`:
The only place $n_2$ appears is in calculating:
$$j = \text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(n_2, 0)))$$
Since $\text{alt}$ was chosen specifically such that:
$$\text{extract\_upper}(\text{AES}_{k_1}(\text{format\_block}(\text{alt}, 0))) = j$$
The variables $w_1, w_2, r_1, r_2$ are **identical** whether computed with $n_2$ or $\text{alt}$.

Consequently:
$$\text{state}(k_1, n_1, n_2) = \text{state}(k_1, n_1, \text{alt})$$
$$\implies \text{derive\_keys}(k_2, n_1, \text{state}(n_2)) = \text{derive\_keys}(k_2, n_1, \text{state}(\text{alt}))$$
The derived AES-GCM key $ek$ and $iv$ for encrypting the flag with $(n_1, n_2)$ and encrypting the sample with $(n_1, \text{alt})$ are **completely identical**.

### Flaw 3: Keystream Reuse in AES-GCM
AES-GCM encrypts plaintext using AES-CTR mode:
$$C = P \oplus \text{Keystream}(ek, iv)$$
For the known plaintext sample $m = 0^{128}$:
$$C_{\text{sample}} = 0^{128} \oplus \text{Keystream} = \text{Keystream}$$
Because $(ek, iv)$ is the same for the flag encryption:
$$C_{\text{flag}} = \text{flag} \oplus \text{Keystream}$$
$$\therefore \text{flag} = C_{\text{flag}} \oplus C_{\text{sample}}$$

---

## 3. Exploit Steps

### Step 1: Brute-Force the 32-bit Seed
We implement a multi-threaded C program using OpenSSL `SHA256` to search for `seed` matching hint `a`:
```c
for (uint64_t s = start; s < end; s++) {
    SHA256_CTX ctx = ctx_base;
    uint8_t s_bytes[4] = {(s >> 24) & 0xff, (s >> 16) & 0xff, (s >> 8) & 0xff, s & 0xff};
    SHA256_Update(&ctx, s_bytes, 4);
    SHA256_Final(digest, &ctx);
    if (memcmp(digest, target, 32) == 0) {
        printf("Found seed: %u\n", (uint32_t)s);
    }
}
```
**Result**: `seed = 583324655` (`0x22c4d3ef`).

### Step 2: Compute $k_1$ and Search for Collision $\text{alt}$
We compute:
$$k_1 = \text{SHA256}(\texttt{"K1-SEED"} \parallel 583324655)$$
$$T = \text{extract\_upper}(\text{AES}_{k_1}(n_2 \ll 32))$$
We search over 32-bit values $\text{sep} \in [0, 2^{32}-1]$ to find decrypts:
$$X = \text{AES}_{k_1}^{-1}((T \ll 32) \mid \text{sep})$$
such that $(X \pmod{2^{32}}) == 0$ and $X \gg 32 \neq n_2$.

**Result**: $\text{alt} = \texttt{0xa5720dc7719f529e8e9cb565}$.

### Step 3: Decrypt the Ticket and Recover Keystream
Using $k_1$, $n_1$, and $\text{alt}$, derive $K_{\text{seal}}$ and $IV_{\text{seal}}$:
```python
key = sha256(b"SEALED-TICKET-KEY" + k1 + n1.to_bytes(12, "big") + alt.to_bytes(12, "big")).digest()[:16]
nonce = sha256(b"SEALED-TICKET-IV" + key).digest()[:12]
c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
blob = c.decrypt_and_verify(ticket_ct, ticket_tag)
record = json.loads(blob.decode())
sample_ct = bytes.fromhex(record["x"]["c"])
```

### Step 4: Recover the Flag
XOR the flag ciphertext with the recovered keystream:
```python
flag_ct = bytes.fromhex(data["y"]["c"])
flag = bytes([ct ^ ks for ct, ks in zip(flag_ct, sample_ct[:len(flag_ct)])])
print(flag.decode())
```

---

## 4. Complete Solve Script
```python
#!/usr/bin/env python3
import json
from hashlib import sha256
from Crypto.Cipher import AES

# 1. Recovered seed
seed = 583324655
k1 = sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()

# 2. Parse challenge data
data = json.load(open("challenge.json"))
n1 = int(data["n"][0], 16)
n2 = int(data["n"][1], 16)

# 3. Collision alt found
alt = int("a5720dc7719f529e8e9cb565", 16)

# 4. Decrypt ticket z
key = sha256(b"SEALED-TICKET-KEY" + k1 + n1.to_bytes(12, "big") + alt.to_bytes(12, "big")).digest()[:16]
nonce = sha256(b"SEALED-TICKET-IV" + key).digest()[:12]

c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
ticket_ct = bytes.fromhex(data["z"]["c"])
ticket_tag = bytes.fromhex(data["z"]["t"])
blob = c.decrypt_and_verify(ticket_ct, ticket_tag)
record = json.loads(blob.decode())

# 5. Keystream reuse XOR
sample_ct = bytes.fromhex(record["x"]["c"])
flag_ct = bytes.fromhex(data["y"]["c"])
flag = bytes([ct ^ ks for ct, ks in zip(flag_ct, sample_ct[:len(flag_ct)])])

print("Flag:", flag.decode("utf-8"))
```

---

## 5. Flag
```text
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```
