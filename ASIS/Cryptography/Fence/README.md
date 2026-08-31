# fence — Writeup

**Category:** Crypto
**Files:** `fence.py`, `flag.enc`
**Flag:** `ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}`

## TL;DR

`fence.py` is a custom NTRU-like cryptosystem where the *private* key material
`(a, b)` — not a shared secret derived from the public key `h` — is fed
straight into the symmetric-key derivation function. Anyone who can recover
`(a, b)` from the published `h = b·a⁻¹ mod q` can decrypt. Because the
private polynomials are extremely dense and short relative to the modulus,
the standard NTRU lattice attack (LLL → BKZ) recovers each key in well under
a minute. The flag itself is secret-shared as an XOR one-time-pad across
five independent NTRU instances, so all five keys had to be broken and the
five plaintext shares XORed together.

## 1. Understanding `fence.py`

The ring in use is `R_q = Z_q[x] / (x^n + 1)` with:

```python
n = 128
q = 268435361      # ~2^28, prime
w = 80              # Hamming weight of secret polynomials
r = 5               # number of independent shares
```

### 1.1 Key generation

```python
def gn():
    # ternary polynomial: w/2 coefficients = +1, w/2 = -1, rest 0
    ...
```

`gn()` produces a ternary polynomial of degree < n with exactly `w/2 = 40`
coefficients equal to `+1`, `40` equal to `-1`, and the remaining `48`
coefficients zero. This is *very* dense compared to a normal NTRU key
(usually only a small fraction of coefficients are nonzero) — a detail that
turns out to matter a lot for the attack.

Two such polynomials `a, b` are sampled, and the public value is:

```python
h = pm(b, iv(a))     # h = b * a^{-1} mod (x^n+1, q)
```

`pm` is negacyclic polynomial multiplication mod `x^n+1`, and `iv` is
modular inversion in the same ring via an extended-Euclidean-style
algorithm. This is exactly the classic NTRU public key relation:

```
a * h ≡ b   (mod q, mod x^n+1)
```

### 1.2 The actual bug: key derivation uses the *private* polynomials

```python
def ky(a, b, s):
    u = min(tuple(sh(a, i) + sh(b, i)) for i in range(2 * n))
    return hashlib.sha3_256(d + s + bytes(i + 1 for i in u)).digest()
```

`ky()` takes the **private** `a` and `b` directly (not `h`, not a shared
KEM secret) and derives a symmetric key by taking a canonical
(rotation-and-sign-normalized) representative of the concatenation of `a`
and `b`, then hashing it. `en()`/`dc()` use this key with SHAKE-256 as a
stream cipher plus an HMAC tag.

In `main()`:

```python
h = pm(b, iv(a))
...
cs.append(en(a, b, h, m))
```

So the same party that generates `(a, b)` immediately uses `(a, b)` itself
(not any public/shared value) to encrypt. This means: **whoever can recover
`(a, b)` from the published `h` can derive the exact same symmetric key and
decrypt** — there's no additional secret protecting the ciphertext beyond
the hardness of inverting the NTRU public key. This is the entire
vulnerability; everything else is just "break NTRU."

### 1.3 The secret-sharing wrapper

```python
acc = [0] * len(flag)
for idx in range(r):
    a, b = gn(), gn()
    h = pm(b, iv(a))
    if idx < r - 1:
        m = secrets.token_bytes(len(flag))
        acc = [i ^ j for i, j in zip(acc, m)]
    else:
        m = bytes(i ^ j for i, j in zip(acc, flag))
    hs.append(h); cs.append(en(a, b, h, m))
```

Five independent NTRU keypairs are generated. The first four encrypt random
padding shares `m_0..m_3`; the fifth encrypts `flag XOR (m_0^m_1^m_2^m_3)`.
Therefore:

```
flag = m_0 ^ m_1 ^ m_2 ^ m_3 ^ m_4
```

All five ciphertexts must be broken to recover the flag — breaking any
subset only gives you random garbage.

## 2. Attack plan

For each of the 5 published `h_i`:

1. Recover the ternary secret pair `(a_i, b_i)` from `h_i` via lattice
   reduction (NTRU key recovery).
2. Recompute the symmetric key with `ky(a_i, b_i, s_i)` exactly as the
   original code does.
3. Verify/decrypt with `dc()` (checks the HMAC tag, then undoes the
   SHAKE-256 keystream) to get `m_i`.
4. XOR all five `m_i` together to get the flag.

Step 1 is the interesting part.

### 2.1 Building the NTRU lattice

`pm(a, b)` computes negacyclic convolution: for output index `m`,

```
c_m = Σ_i a_i * b_{(m-i) mod n} * sign(i, m),   sign = +1 if i ≤ m else -1
```

This lets us write `h`'s action as a linear map: define the `n×n` matrix

```
B[i][m] = sign(i, m) * h[(m - i) mod n]
```

so that `a @ B ≡ b (mod q)` for the private `(a, b)` pair, matching
`a * h ≡ b`.

The standard NTRU lattice is then the row span of the `2n × 2n` matrix

```
M = [ I_n    B   ]
    [ 0    q·I_n ]
```

The private vector `(a, b)` lies in this lattice: `a·B - b ≡ 0 (mod q)`
means `a·B - b = q·t` for some integer vector `t`, and

```
(a, a·B) - t·(0, q·I_n) = (a, a·B - q·t) = (a, b)
```

is an integer combination of the rows of `M`, i.e. a lattice vector — and a
very short one, since every coefficient of `a` and `b` is in `{-1, 0, 1}`.

### 2.2 Why this is an "easy" SVP instance

`det(M) = q^n` (the block-triangular structure makes this immediate), so
the Gaussian heuristic predicts a shortest vector of length

```
GH ≈ sqrt(dim / 2πe) · det(M)^(1/dim)
   = sqrt(256 / 2πe) · q^(1/2)
   ≈ 3.87 × 16384 ≈ 63,400
```

But `‖(a, b)‖ = sqrt(80 + 80) = sqrt(160) ≈ 12.65` — about **5000× shorter**
than the Gaussian heuristic predicts. That enormous gap is what makes this
solvable by commodity lattice reduction rather than requiring a serious
BKZ run: plain LLL alone wasn't quite strong enough in practice (its
returned vectors bottomed out around norm ~130–150 for these instances),
but a handful of BKZ rounds with modest block size closed the gap
completely.

### 2.3 Running the reduction

Using `fpylll`:

```python
from fpylll import IntegerMatrix, LLL, BKZ
from fpylll.algorithms.bkz2 import BKZReduction

M = build_lattice(h)      # the 256x256 matrix above
LLL.reduction(M)           # fast pre-reduction (~5s)

for block_size in [10, 15, 20, 25, 30, 35, 40]:
    bkz = BKZReduction(M)
    bkz(BKZ.Param(block_size=block_size, max_loops=8))
    # inspect row norms / search for a {-1,0,1}-only row
```

In practice:

| index | block size where found | wall time |
|-------|------------------------|-----------|
| 0     | 20                     | ~30s      |
| 1     | 25                     | ~35s      |
| 2     | 25                     | ~35s      |
| 3     | 25                     | ~35s      |
| 4     | 25                     | ~35s      |

Each run produced a basis row with norm exactly `√160 ≈ 12.649` and every
entry in `{-1, 0, 1}` — an unambiguous hit. (Its negation is an equally
valid lattice vector and also decrypts correctly, since `ky` normalizes
over all cyclic shifts of both `a` and `b` but not over global sign — in
practice both signs were tried per key.)

## 3. Decryption

With `(a_i, b_i)` recovered for each `i`, the private-key-derived symmetric
key reproduces exactly:

```python
def ky(a, b, s):
    u = min(tuple(sh(a, i) + sh(b, i)) for i in range(2 * n))
    return hashlib.sha3_256(d + s + bytes(i + 1 for i in u)).digest()

def dc(a, b, h, z):
    s, c, t = bytes.fromhex(z["S"]), bytes.fromhex(z["C"]), bytes.fromhex(z["T"])
    k = ky(a, b, s)
    u = json.dumps({"N": n, "Q": q, "H": h}, sort_keys=True, separators=(",", ":")).encode()
    assert hmac.compare_digest(t, hmac.new(k, d + u + s + c, hashlib.sha256).digest()[:16])
    z2 = hashlib.shake_256(d + k + s).digest(len(c))
    return bytes(i ^ j for i, j in zip(c, z2))
```

All five ciphertexts verified and decrypted cleanly (57-byte plaintexts).
XOR-combining the five shares:

```python
flag = bytes(0 for _ in range(57))
for m in [m0, m1, m2, m3, m4]:
    flag = bytes(x ^ y for x, y in zip(flag, m))
```

gives:

```
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```

## 4. Root cause & how it should have been fixed

The design mistakes, in order of severity:

1. **Symmetric key derived from the private key material, not a KEM shared
   secret.** A correct NTRU-based hybrid encryption scheme derives the
   symmetric key from something only the legitimate encapsulator/decapsulator
   can compute (e.g. hashing a randomly sampled message polynomial that is
   itself encrypted under `h`, à la NTRU-KEM), never from the long-term
   private key directly. Here, recovering `(a, b)` from `h` is *equivalent*
   to breaking confidentiality outright — there's no separation between
   "key recovery" and "message recovery."
2. **Oversized secret weight.** `w = 80` out of `n = 128` (62.5% of
   coefficients nonzero) is far denser than secure NTRU parameterizations
   (which keep weight low, e.g. `w ≈ 2√n` or similar, precisely to keep the
   private-key vector's norm close to the lattice's expected shortest-vector
   length and thus resistant to lattice reduction). Here the private key
   vector was ~5000× shorter than the Gaussian heuristic, making it trivial
   to find.
3. **No KEM/IND-CCA transform, no padding/re-encryption check** — the
   scheme is a bare textbook NTRU relation used as if it were a Diffie–
   Hellman-style shared secret.

Either flaw alone (weak parameters *or* deriving the key from private
material) would have been exploitable in isolation; combined, the challenge
fell in minutes.

## 5. Tooling

- `fpylll` (LLL + BKZ2) for lattice reduction — installed via `pip` with
  system `libfplll-dev` / `libgmp-dev` / `libmpfr-dev`.
- Plain Python for reimplementing `pm`, `ky`, `dc` to perform the final
  decryption once `(a, b)` was known.

Total attack time: a few seconds of LLL + tens of seconds of BKZ per key,
five keys, well under 5 minutes of compute.
