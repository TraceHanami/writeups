# Cyclotomic Echo — Cryptography Challenge Writeup

## Challenge Information
- **Challenge Name:** Cyclotomic Echo
- **Category:** Cryptography (Lattice-Based Cryptography / NTRU / Hawk Signatures)
- **Target Remote:** `cyclotomic-echo-9a97f66ba0bc.chals.z0d1ak.org:1337` (SSL)
- **Provided Files:**
  - `verifier.py`: Verification logic using cyclotomic polynomial arithmetic.
  - `recovery.json`: Recovered secret polynomials $(f, g, F, G)$.

---

## 1. Problem Description & Background

The challenge implements a lattice-based signature scheme that closely mirrors the **Hawk** signature scheme over the cyclotomic polynomial ring:
$$\mathcal{R} = \mathbb{Z}[x] / (x^N + 1) \quad \text{with } N = 128$$

### Key Structures
1. **Secret Basis Matrix ($B$):**
   $$B = \begin{pmatrix} f & g \\ F & G \end{pmatrix} \in \mathcal{R}^{2 \times 2}$$
   where $f, g, F, G$ are short polynomials in $\mathcal{R}$ satisfying the NTRU relation:
   $$\det(B) = f G - g F = 1$$

2. **Public Key Matrix ($Q$):**
   $$Q = B B^\dagger = \begin{pmatrix} q_{00} & q_{10}^\dagger \\ q_{10} & q_{11} \end{pmatrix}$$
   where:
   - $f^\dagger(x) = f(x^{-1}) = f_0 - \sum_{i=1}^{N-1} f_{N-i} x^i$ is the canonical involution (conjugate/adjoint) in $\mathcal{R}$.
   - $q_{00} = f f^\dagger + g g^\dagger$
   - $q_{10} = F f^\dagger + G g^\dagger$
   - $q_{11} = F F^\dagger + G G^\dagger = \frac{1 + q_{10} q_{10}^\dagger}{q_{00}}$

---

## 2. Verification Mechanism

When verifying a signature $(t, u)$ (where $t$ is a 16-byte salt and $u = s_1 \in \mathcal{R}$) for target message $m$:
1. A hash $(x, y) = H(m, t)$ is generated using SHAKE256, outputting two binary polynomials $x, y \in \{0, 1\}^N$.
2. The verifier recovers the first half of the secret error vector $v$ by rounding:
   $$v = \left\lfloor \frac{x}{2} + \left(\frac{y}{2} - u\right) \frac{q_{10}}{q_{00}} \right\rceil$$
3. The full error vector is computed as:
   $$e = (e_0, e_1) = (x - 2v, \, y - 2u)$$
4. The verifier checks:
   - **Sign condition:** $S(e_1) = \text{True}$ (the first non-zero coefficient of $e_1$ must be positive).
   - **Norm condition:** 
     $$z = e Q e^\dagger = \|e B\|_2^2 \le \text{VERIFY\_BOUND} = 2N(2 \times 4)^2 = 16384$$

---

## 3. Vulnerability & Exploitation

In `recovery.json`, the challenge author leaked the complete secret polynomial quadruple:
$$(f, g, F, G)$$

Because we possess the secret basis $B$:
1. The exact inverse matrix is trivially:
   $$B^{-1} = \begin{pmatrix} G & -g \\ -F & f \end{pmatrix}$$
2. For any target hash $(x, y) = H(m, t)$, we project $(x, y)$ onto the lattice basis $B$:
   $$(t_0, t_1) = (x, y) B = (x f + y F, \, x g + y G)$$
3. Rounding each coefficient of $\left(\frac{t_0}{2}, \frac{t_1}{2}\right)$ to the nearest integer $(w_0, w_1)$ yields small fractional residuals:
   $$\text{diff}_0 = t_0 - 2w_0, \quad \text{diff}_1 = t_1 - 2w_1 \quad (\text{coefficients in } \{-1, 0, 1\})$$
4. We pull back this short difference vector through $B^{-1}$:
   $$(e_0, e_1) = (\text{diff}_0, \text{diff}_1) B^{-1} = (\text{diff}_0 \cdot G - \text{diff}_1 \cdot F, \, -\text{diff}_0 \cdot g + \text{diff}_1 \cdot f)$$
5. Since $(\text{diff}_0, \text{diff}_1) \equiv (t_0, t_1) \pmod 2$:
   $$(e_0, e_1) \equiv (x, y) \pmod 2$$
   Hence $u = \frac{y - e_1}{2} \in \mathbb{Z}^N$ is strictly integral.
6. The resulting quadratic form norm is simply:
   $$\|e\|_Q^2 = \|\text{diff}_0\|_2^2 + \|\text{diff}_1\|_2^2 \le 2N \cdot 1^2 = 256 \ll 16384$$
7. We test sequential salt values $t$ until $S(e_1)$ is positive, format the forgery JSON, and submit it to the live server.

---

## 4. Solve Script

```python
#!/usr/bin/env python3
import hashlib
import json
import socket
import ssl

N = 128
_D = bytes.fromhex("6379636c6f746f6d69632d6563686f2f7369676e2f7632")

def poly_mul(a, b):
    res = [0] * N
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            idx = i + j
            if idx < N:
                res[idx] += ai * bj
            else:
                res[idx - N] -= ai * bj
    return res

def poly_sub(a, b):
    return [x - y for x, y in zip(a, b)]

def poly_add(a, b):
    return [x + y for x, y in zip(a, b)]

def H(j: dict, t: bytes):
    m = bytes.fromhex(j["target_hex"])
    d = hashlib.shake_256(
        _D + bytes.fromhex(j["instance_id"]) + len(m).to_bytes(4, "little") + m + t
    ).digest(N // 4)
    b_bits = [(d[i >> 3] >> (i & 7)) & 1 for i in range(2 * N)]
    return b_bits[:N], b_bits[N:]

def S(vec):
    for val in vec:
        if val != 0:
            return val > 0
    return False

def solve():
    with open("crypto_cyclotomic-echo/dist/recovery.json", "r") as f:
        data = json.load(f)
    F, G, f_poly, g_poly = data["F"], data["G"], data["f"], data["g"]

    host = "cyclotomic-echo-9a97f66ba0bc.chals.z0d1ak.org"
    port = 1337

    sock = socket.create_connection((host, port))
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(sock, server_hostname=host)
    stream = ss.makefile("rw")

    instance_line = stream.readline()
    print("[*] Instance received:", instance_line.strip())
    server_inst = json.loads(instance_line)

    for attempt in range(200):
        salt = attempt.to_bytes(16, "little")
        x, y = H(server_inst, salt)

        t0 = poly_add(poly_mul(x, f_poly), poly_mul(y, F))
        t1 = poly_add(poly_mul(x, g_poly), poly_mul(y, G))

        w0 = [round(v / 2.0) for v in t0]
        w1 = [round(v / 2.0) for v in t1]

        diff0 = [v - 2 * w for v, w in zip(t0, w0)]
        diff1 = [v - 2 * w for v, w in zip(t1, w1)]

        e0 = poly_sub(poly_mul(diff0, G), poly_mul(diff1, F))
        e1 = poly_add(poly_mul([-v for v in diff0], g_poly), poly_mul(diff1, f_poly))

        if not S(e1):
            continue

        u = [(y[i] - e1[i]) // 2 for i in range(N)]
        forgery = {"salt_hex": salt.hex(), "s1": u}
        print(f"[+] Forgery found on salt attempt {attempt}!")
        break

    payload = json.dumps(forgery, separators=(",", ":"))
    stream.write(payload + "\n")
    stream.flush()

    response = stream.readline()
    print("[*] Server Response:", response.strip())

if __name__ == "__main__":
    solve()
```

---

## 5. Flag
```
zdk{CycLotoMIc_echO_on3_BaSi5_biND5_ev3RY_7E4m_ArChIv3}
```
