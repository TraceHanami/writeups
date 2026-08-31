# Sultan — ASIS CTF Writeup

- **Category:** Cryptography
- **Flag:** `ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}`

---

## 1. Challenge Overview

We are given a web application (`app.py`) running a custom lattice-based cryptosystem (`crypto_engine.py`):
- Per user session, a random alphanumeric secret string (28–32 chars) is generated.
- `GET /api/encrypt`: Returns an encrypted binary blob (`secret.enc`) containing the encryption of the session secret string.
- `POST /api/verify`: Verifies the submitted secret string and returns the flag upon matching.

Our objective is to recover the secret string from a single ciphertext download and submit it within the session's 20-minute expiration window.

---

## 2. Cryptographic Scheme Analysis

The underlying cryptosystem operates over the polynomial quotient ring $R_q = \mathbb{Z}_q[x] / (x^n + 1)$ with the parameters:
- Modulus $q = 8380417$
- Degree $n = 64$
- Dimension $\ell = 1$
- Number of transcript samples $m = 70$
- Challenge polynomial Hamming weight $t = 16$
- Rounding bucket base $b = 65000$
- Secret coefficient bound $B = 3$ (so $s_j \in [-3, 3]$)

### Key Generation and Ciphertext Structure
1. A small secret polynomial $s(x) \in R_q$ is generated with $\|s\|_\infty \le 3$.
2. The key $k = \text{SHAKE256}(\texttt{"SULTAN/key"} \mathbin{\Vert} s)$ encrypts the secret string via a stream cipher with a 24-byte nonce $N$, authenticated via BLAKE2s.
3. The ciphertext contains $m = 70$ samples of:
   - Challenge seed deriving sparse challenge $c_i(x)$ (weight 16 in $\{-1, 1\}$) and audit vector $r_i \in \mathbb{Z}_q^n$.
   - Masked polynomial $v_i(x) = u_i(x) + c_i(x) \cdot s(x) \pmod q$, where $u_i(x)$ is random.
   - Rounded inner product $I_i = \lfloor \langle r_i, u_i \rangle / b \rfloor$.

---

## 3. Vulnerability: Low-Noise LWE Reduction

From the transcript relations:
$$\langle r_i, u_i \rangle \equiv \langle r_i, v_i \rangle - \langle r_i, c_i \cdot s \rangle \pmod q$$

From $I_i = \lfloor \langle r_i, u_i \rangle / b \rfloor$:
$$\langle r_i, u_i \rangle = I_i \cdot b + \varepsilon_i$$
where $\varepsilon_i \in [0, b - 1]$.

Equating both expressions modulo $q$:
$$\langle r_i, c_i \cdot s \rangle \equiv \langle r_i, v_i \rangle - I_i \cdot b - \varepsilon_i \pmod q$$

Let $\mathbf{C}_i \in \mathbb{Z}_q^{n \times n}$ be the negacyclic convolution matrix for polynomial multiplication by $c_i(x) \pmod{x^n + 1}$. Then:
$$(r_i^T \mathbf{C}_i) \mathbf{s} \equiv \langle r_i, v_i \rangle - I_i \cdot b - \frac{b}{2} + \left(\frac{b}{2} - \varepsilon_i\right) \pmod q$$

Defining:
- $\mathbf{a}_i^T = (r_i^T \mathbf{C}_i) \pmod q \in \mathbb{Z}_q^{1 \times n}$
- $y_i = \left( \langle r_i, v_i \rangle - I_i \cdot b - \frac{b}{2} \right) \pmod q$
- $e_i = \frac{b}{2} - \varepsilon_i \implies |e_i| \le \frac{b}{2} = 32500$

This yields an overdetermined system of Learning With Errors (LWE) equations:
$$\mathbf{A} \mathbf{s} \equiv \mathbf{y} + \mathbf{e} \pmod q$$
where $\mathbf{A} \in \mathbb{Z}_q^{70 \times 64}$, $\mathbf{s} \in [-3, 3]^{64}$, and the noise $|e_i| \le 32500 \ll q = 8380417$.

---

## 4. Exploitation via Kannan's Embedding

We construct a Kannan embedding lattice of dimension $(m + n + 1) = 135$:

$$\mathbf{B} = \begin{pmatrix}
q \mathbf{I}_m & \mathbf{0}_{m \times n} & \mathbf{0}_{m \times 1} \\
\mathbf{A}^T & W_s \mathbf{I}_n & \mathbf{0}_{n \times 1} \\
\mathbf{y}^T & \mathbf{0}_{1 \times n} & M
\end{pmatrix}$$

With weight scalings $W_s = 15000$ and $M = 32500 \approx \frac{b}{2}$, the target vector is:
$$\mathbf{v}_{\text{target}} = (-\mathbf{k}, \mathbf{s}, -1) \mathbf{B} = (\mathbf{e}, \; W_s \mathbf{s}, \; -M)$$

We reduce the lattice with **LLL** followed by **BKZ-15** using `fpylll`. The reduction completes in ~7 seconds and immediately yields the exact secret vector $\mathbf{s}$, which is used to decrypt the payload.

---

## 5. Solver Script

The complete automated exploit is implemented in `solve_remote.py`.

```bash
python3 solve_remote.py http://91.107.152.21:17131
```

### Execution Output:
```text
[*] Connecting to http://91.107.152.21:17131...
[+] Downloaded ciphertext: 19656 bytes.
[*] Lattice size: 135x135. Reducing with LLL...
[*] LLL finished in 0.48s.
[*] Running BKZ-15...
[*] BKZ-15 finished in 6.22s.
[+] Successfully recovered secret string: QUu45wmWECj7qO7kUqYGUHNTkzrHkW8
[+] Verification response (200):
{'flag': 'ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}', 'message': 'Congratulations! Secret verified correctly.', 'success': True}
```
