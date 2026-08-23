# Siren (Cryptography) — CTF Writeup

- **Challenge Name:** Siren (`crypto_siren`)
- **Category:** Cryptography
- **Curve:** `secp256k1` (ECDSA)
- **Flag:** `zdk{4_f3W_8LTS_PeR_516n47uR3_Slnk5_TH3_kEY}`

---

## Executive Summary

The **Siren** challenge implements standard ECDSA signing and verification over the `secp256k1` curve. However, the nonce ($k$) generation routine introduces a critical flaw: the most significant 10 bits of every signing nonce are deterministically fixed and computable by the client.

This deterministic MSB leakage maps directly to the **Hidden Number Problem (HNP)**. By requesting ~40 signatures from the oracle, constructing an appropriately scaled Kannan-embedding lattice, and running **LLL (Lenstra–Lenstra–Lovász)** basis reduction, we recover the signer's private key $D$. With $D$, we forge a valid signature for the protected message `"unlock:release-the-tide"` to claim the flag.

---

## Challenge Source Analysis

The challenge server source (`siren_server.py`) defines the parameters and commands:

```python
G = SECP256k1.generator
N = SECP256k1.order                      # 256-bit prime group order
NBITS = N.bit_length()                   # == 256

PITCH_BITS = 10
SUFFIX_BITS = NBITS - PITCH_BITS         # 246
SUFFIX_BOUND = 1 << SUFFIX_BITS          # 2^246
SONG_ID = os.urandom(8).hex()

PRIV_MSG = "unlock:release-the-tide"

D = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
Q = D * G                                # public key point
```

### The Vulnerability: Shaped Nonce Generation

The signing routine generates nonces as follows:

```python
def public_pitch(msg):
    material = (SONG_ID + ":" + msg).encode()
    h = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return h >> (256 - PITCH_BITS)

def shaped_nonce(msg):
    prefix = public_pitch(msg) << SUFFIX_BITS
    while True:
        k = prefix | (rng_below(SUFFIX_BOUND) - 1)
        if 1 <= k < N:
            return k
```

Notice:
1. `SONG_ID` is provided publicly via the `pubkey` command.
2. For any query `msg`, `public_pitch(msg)` is completely known to the attacker.
3. The nonce $k$ is structured as:
   $$k = (\text{prefix} \ll 246) + \text{suffix} = \text{prefix} \cdot 2^{246} + \text{suffix}$$
   where $\text{prefix} \in [0, 2^{10}-1]$ is known, and $0 \le \text{suffix} < 2^{246}$.

Every signature leaks the **top 10 bits** of its nonce.

---

## Mathematical Formulation: Hidden Number Problem

In ECDSA, the signature $(r_i, s_i)$ on message hash $z_i = \text{SHA256}(m_i) \pmod N$ satisfies:

$$s_i \equiv k_i^{-1} (z_i + r_i D) \pmod N$$

Multiplying by $k_i$:
$$s_i k_i \equiv z_i + r_i D \pmod N$$

Substitute $k_i = \text{prefix}_i \cdot 2^{246} + \text{suffix}_i$:
$$s_i (\text{prefix}_i \cdot 2^{246} + \text{suffix}_i) \equiv z_i + r_i D \pmod N$$
$$s_i \cdot \text{suffix}_i \equiv z_i + r_i D - s_i \cdot \text{prefix}_i \cdot 2^{246} \pmod N$$

Multiply both sides by $s_i^{-1} \pmod N$:
$$\text{suffix}_i \equiv s_i^{-1} (z_i - s_i \cdot \text{prefix}_i \cdot 2^{246}) + (s_i^{-1} r_i) D \pmod N$$

Define the known values:
- $\alpha_i = s_i^{-1}(z_i - s_i \cdot \text{prefix}_i \cdot 2^{246}) \pmod N$
- $t_i = s_i^{-1} r_i \pmod N$

This yields the canonical HNP relation:
$$\text{suffix}_i \equiv \alpha_i + t_i D \pmod N, \quad 0 \le \text{suffix}_i < 2^{246}$$

Since each equation bounds the unknown $\text{suffix}_i$ to $\approx N / 2^{10}$, collecting $m \ge \lceil 256 / 10 \rceil \approx 30 \text{--} 40$ signatures allows us to formulate this as a **Closest Vector Problem (CVP)** or **Shortest Vector Problem (SVP)** in a lattice.

---

## Lattice Construction & Scaling

For $m$ collected signatures, we construct an $(m + 2) \times (m + 2)$ integer lattice matrix $M$. 

Because the unknown suffixes are bounded by $2^{246} = 2^{256} / 2^{10}$, we scale the modular equations by $2^{10} = 1024$ so all coordinates in the target vector have comparable magnitudes ($\approx 2^{256}$):

$$
M = \begin{pmatrix}
N \cdot 2^{10} & 0 & \dots & 0 & 0 & 0 \\
0 & N \cdot 2^{10} & \dots & 0 & 0 & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & N \cdot 2^{10} & 0 & 0 \\
t_0 \cdot 2^{10} & t_1 \cdot 2^{10} & \dots & t_{m-1} \cdot 2^{10} & 1 & 0 \\
\alpha_0 \cdot 2^{10} & \alpha_1 \cdot 2^{10} & \dots & \alpha_{m-1} \cdot 2^{10} & 0 & N
\end{pmatrix}
$$

The linear combination of rows taking:
$$\vec{c} = (k_0, k_1, \dots, k_{m-1}, D, -1)$$
produces the vector:
$$\vec{v} = (\text{suffix}_0 \cdot 2^{10},\; \text{suffix}_1 \cdot 2^{10},\; \dots,\; \text{suffix}_{m-1} \cdot 2^{10},\; D,\; -N)$$

Since each $\text{suffix}_i < 2^{246}$, we have $\text{suffix}_i \cdot 2^{10} < 2^{256} \approx N$. The vector $\vec{v}$ is extraordinarily short compared to the generic lattice determinant:
$$\det(L) = N^m \cdot 2^{10m} \cdot N = N^{m+1} \cdot 2^{10m}$$

Gaussian heuristic expects vectors of size $\approx \sqrt{m+2} \cdot \det(L)^{1/(m+2)} \gg \|\vec{v}\|$, meaning LLL will easily isolate $\vec{v}$.

Inspecting the $(m)$-th column of the reduced basis vectors reveals $\pm D \pmod N$.

---

## Exploitation Pipeline

1. **Information Gathering:** Connect to the remote instance using `ncat --ssl`. Query `pubkey` to obtain public key $Q = (Q_x, Q_y)$, curve order $N$, and `song_id`.
2. **Signature Collection:** Query `sign` for 40 distinct messages (`note_0`, `note_1`, ...).
3. **Lattice Reduction:**
   - Compute $(\alpha_i, t_i)$ for all $i \in [0, 39]$.
   - Construct the $42 \times 42$ scaled matrix.
   - Run `fpylll.LLL.reduction(M)`.
   - Test each basis row: verify if $d \cdot G == Q$.
4. **Key Recovery:**
   - Private key recovered: `0x75dfeaaa9d5469e55b6fb28a1a83911d18826810f675ba70e6a30fa1b733f1eb`
5. **Signature Forgery:**
   - Generate an ECDSA signature on `PRIV_MSG = "unlock:release-the-tide"` using standard random nonces.
   - Send `{"cmd": "unlock", "r": hex(r), "s": hex(s)}`.
6. **Flag:** The server verifies our signature and returns the flag.

---

## Standalone Exploit Script

```python
#!/usr/bin/env python3
"""
Siren CTF Exploit - Biased Nonce ECDSA Attack via LLL (HNP)
Target: siren-7e34b81ae4b8.chals.z0d1ak.org:1337
"""

import subprocess
import json
import hashlib
import random
import sys
from fpylll import IntegerMatrix, LLL

# secp256k1 domain parameters
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G_PT = (Gx, Gy)

PITCH_BITS = 10
SUFFIX_BITS = 256 - PITCH_BITS  # 246

def modinv(a, m):
    return pow(a, -1, m)

def ec_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, Pt):
    R = None
    Q = Pt
    k = k % N
    while k > 0:
        if k & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        k >>= 1
    return R

def msg_hash(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N

def public_pitch(song_id, msg):
    material = (song_id + ":" + msg).encode()
    h = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return h >> (256 - PITCH_BITS)

def sign_with_key(d, msg):
    z = msg_hash(msg)
    while True:
        k = random.randint(1, N - 1)
        R = ec_mul(k, G_PT)
        if R is None:
            continue
        r = R[0] % N
        if r == 0:
            continue
        s = (modinv(k, N) * (z + r * d)) % N
        if s == 0:
            continue
        return r, s

def solve_hnp(sigs, Qx, Qy):
    m = len(sigs)
    scale_eq = 1 << PITCH_BITS  # 2^10
    
    M = IntegerMatrix(m + 2, m + 2)
    for i in range(m):
        M[i, i] = N * scale_eq
    
    for i in range(m):
        t_i, a_i = sigs[i]
        M[m, i] = t_i * scale_eq
        M[m + 1, i] = a_i * scale_eq
    
    M[m, m] = 1
    M[m + 1, m + 1] = N
    
    print(f"[*] Running LLL on {m+2}x{m+2} lattice...")
    LLL.reduction(M)
    
    for i in range(m + 2):
        row = [M[i, j] for j in range(m + 2)]
        for sign in [1, -1]:
            d_cand = (sign * row[m]) % N
            if d_cand > 0:
                pt = ec_mul(d_cand, G_PT)
                if pt is not None and pt[0] == Qx and pt[1] == Qy:
                    return d_cand
    return None

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "siren-7e34b81ae4b8.chals.z0d1ak.org"
    port = sys.argv[2] if len(sys.argv) > 2 else "1337"
    
    print(f"[*] Connecting via ncat --ssl to {target}:{port}...")
    p = subprocess.Popen(
        ['ncat', '--ssl', target, port],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    banner = json.loads(p.stdout.readline())
    print("[+] Server banner:", banner)
    
    def query(obj):
        p.stdin.write(json.dumps(obj) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())
    
    pub_info = query({"cmd": "pubkey"})
    print("[+] Pubkey info:", pub_info)
    
    Qx = int(pub_info["Qx"], 16)
    Qy = int(pub_info["Qy"], 16)
    song_id = pub_info["song_id"]
    priv_msg = pub_info["priv_msg"]
    
    NUM_SIGS = 40
    print(f"[*] Requesting {NUM_SIGS} signatures...")
    sigs = []
    for i in range(NUM_SIGS):
        msg = f"siren_melody_note_{i}"
        resp = query({"cmd": "sign", "msg": msg})
        r = int(resp["r"], 16)
        sv = int(resp["s"], 16)
        z = msg_hash(msg)
        pitch = public_pitch(song_id, msg)
        prefix = pitch << SUFFIX_BITS
        
        s_inv = modinv(sv, N)
        a_i = (s_inv * z - prefix) % N
        t_i = (s_inv * r) % N
        sigs.append((t_i, a_i))
    
    print(f"[+] {len(sigs)} signatures collected. Solving HNP via LLL...")
    d = solve_hnp(sigs, Qx, Qy)
    
    if d is None:
        print("[-] Could not recover private key.")
        p.kill()
        return
        
    print(f"\n[+] RECOVERED PRIVATE KEY: {hex(d)}")
    r_forge, s_forge = sign_with_key(d, priv_msg)
    print(f"[*] Forged signature for '{priv_msg}':")
    print(f"    r = {hex(r_forge)}")
    print(f"    s = {hex(s_forge)}")
    
    print("[*] Submitting to unlock...")
    flag_resp = query({"cmd": "unlock", "r": hex(r_forge), "s": hex(s_forge)})
    print("\n" + "=" * 60)
    print("FLAG RESPONSE:")
    print(json.dumps(flag_resp, indent=2))
    print("=" * 60)
    
    p.kill()

if __name__ == "__main__":
    main()
```

---

## Output & Flag

```text
[*] Connecting via ncat --ssl to siren-7e34b81ae4b8.chals.z0d1ak.org:1337...
[+] Server banner: {'banner': 'The Siren hums on the rocks. Send her a line to sign.', 'hint': 'cmds: pubkey | sign{msg} | unlock{r,s}'}
[+] Pubkey info: {'curve': 'secp256k1', 'Qx': '0x68a50ee650d382418b5e80d7307927b2dbbf921ef867cda908dd3767dbcf409', 'Qy': '0x58b3e028323ddfe80d29257d1e57f15536c6962a6d824dbbc6ef755256846d95', 'n': '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'song_id': 'fdaadf0bc1070068', 'pitch_bits': 10, 'priv_msg': 'unlock:release-the-tide'}
[*] Requesting 40 signatures...
[+] 40 signatures collected. Solving HNP via LLL...
[*] Running LLL on 42x42 lattice...

[+] RECOVERED PRIVATE KEY: 0x75dfeaaa9d5469e55b6fb28a1a83911d18826810f675ba70e6a30fa1b733f1eb
[*] Forged signature for 'unlock:release-the-tide':
    r = 0xeabd682d4f035a2cbd354c62c563471f1fdf0251404b32df2e19d2b8db4f338a
    s = 0x1036c5d7e08079e026827fabfcad1432e291e7aa42a692721bfbc822ed6ffc51
[*] Submitting to unlock...

============================================================
FLAG RESPONSE:
{
  "flag": "zdk{4_f3W_8LTS_PeR_516n47uR3_Slnk5_TH3_kEY}"
}
============================================================
```

**Flag:**
```
zdk{4_f3W_8LTS_PeR_516n47uR3_Slnk5_TH3_kEY}
```
