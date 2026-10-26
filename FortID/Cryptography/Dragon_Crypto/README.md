# FortID CTF — Dragon Crypto

**Category:** Cryptography  
**CTF Event:** FortID CTF  
**Artifacts:**
- `Dragon-Crypto/` repository directory
- `handout_extracted/dragon_crypto_repo/`
- Handout source files  
**Status:** In-Progress / Cryptographic Analysis  
**Primitive:** Elliptic Curve Cryptography / Koblitz Message Encoding  

---

## 1. Challenge Overview

Dragon Crypto introduces a custom asymmetric cryptosystem built on elliptic curves over prime fields $\mathbb{F}_p$:
$$y^2 \equiv x^3 + ax + b \pmod p$$
The implementation embeds arbitrary plaintext messages directly into elliptic curve points using a variant of the **Koblitz message encoding algorithm**, followed by an ElGamal-style point multiplication or scalar signature.

---

## 2. Cryptographic Construction

### A. Koblitz Encoding
To represent a plaintext message integer $m$ as a point $P = (x, y) \in E(\mathbb{F}_p)$:
1. Choose an auxiliary parameter $K$ (e.g. $K = 100$).
2. For $j = 0, 1, \dots, K - 1$, set candidate coordinate $x = m \cdot K + j$.
3. Compute $z = x^3 + ax + b \pmod p$.
4. Check whether $z$ is a quadratic residue modulo $p$ using the Legendre symbol:
   $$\left(\frac{z}{p}\right) \equiv z^{(p-1)/2} \pmod p$$
5. If $\left(\frac{z}{p}\right) = 1$, compute $y = \sqrt{z} \pmod p$ using the Tonelli-Shanks algorithm.
6. The point $P = (x, y)$ is a valid curve point representing message $m$.

### B. Weakness & Attack Surface
1. **Low Order / Smooth Group Order:** If curve parameters $(a, b, p)$ define an order $\#E(\mathbb{F}_p)$ that factors into small primes, the Pohlig-Hellman algorithm reduces the discrete logarithm problem to small subgroup checks.
2. **Singular Curve / Trace of Frobenius:** Check whether the curve is singular (discriminant $\Delta = -16(4a^3 + 27b^2) \equiv 0 \pmod p$) or anomalous ($\#E(\mathbb{F}_p) = p$, Smart's attack).
3. **Nonce Reuse:** If the system signs or encrypts using repeated ephemeral scalar $k$, private keys can be derived algebraically through standard ECDSA nonce-leak relations.
