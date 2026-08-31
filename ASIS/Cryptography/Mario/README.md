# ASIS CTF — Mario (Crypto) Writeup

## Challenge Overview

- **Files Provided**: 
  - `mario.py`: Encryption and challenge generation script.
  - `output.txt`: Parameters, public quadratic polynomials, public report samples, and encrypted flag payload.
- **Parameters**:
  - Finite field: $\mathbb{F}_{16} = \mathbb{F}_2[x] / (x^4 + x + 1)$
  - Dimension $n = 96$
  - Number of quadratic polynomials $m = 72$
  - Oil dimension $d = 24$ (Vinegar dimension $v = n - d = 72$)
  - Number of report samples $s = 64$

---

## Analysis

### 1. The Structure of Public Polynomials

In multivariate cryptography (specifically Oil and Vinegar schemes), the system operates over $n$ variables split into vinegar variables ($v = 72$) and oil variables ($d = 24$).

In `build_public_map`:
- The matrix $K \in \mathbb{F}_{16}^{v \times d}$ defines the embedding for the $d$-dimensional oil subspace $\mathcal{O}$:
  $$\text{oil\_embed}(K, x) = \begin{bmatrix} K x \\ x \end{bmatrix} \in \mathbb{F}_{16}^n$$
- For each polynomial $P_k$ ($k \in \{0, \dots, m-1\}$), the quadratic terms involving purely oil-oil indices ($v \le i \le j < n$) are specifically computed such that:
  $$P_k(\text{basis}[i]) = 0 \quad \text{and} \quad P_k(\text{basis}[i] + \text{basis}[j]) \oplus P_k(\text{basis}[i]) \oplus P_k(\text{basis}[j]) = 0$$

Because the polar form $B_k(u, w) = P_k(u + w) \oplus P_k(u) \oplus P_k(w)$ is bilinear and $P_k$ evaluates to zero on all basis elements and their pairs, the entire oil subspace $\mathcal{O}$ is **totally isotropic** for all $m$ quadratic forms:
$$\forall u \in \mathcal{O}, \quad P_k(u) = 0 \quad (\forall k \in \{0, \dots, m-1\})$$

### 2. Monomial Transformation

A secret monomial transformation $M$ (composed of a permutation $\pi$ and non-zero coordinate scaling $\lambda \in (\mathbb{F}_{16}^*)^n$) is applied:
- Transformed polynomials: $P'_k(y) = P_k(M^{-1} y)$
- Transformed oil subspace: $\mathcal{O}' = M(\mathcal{O})$

Since $y \in \mathcal{O}' \iff M^{-1} y \in \mathcal{O}$, every vector in $\mathcal{O}'$ is still a common zero of all public polynomials $A$:
$$\forall u \in \mathcal{O}', \quad P'_k(u) = 0 \quad (\forall k \in \{0, \dots, m-1\})$$

### 3. The Report Leakage

The output contains $s = 64$ reports $B = \{R'_0, R'_1, \dots, R'_{s-1}\}$ constructed as:
$$R'_i = o'_i + c_i \cdot g'$$
where:
- $o'_i \in \mathcal{O}'$
- $c_i \in \mathbb{F}_{16}^*$ (scalar mask)
- $g' = M(g)$ is a fixed secret non-oil vector

Consider any pair $(R'_0, R'_i)$ for $i \ge 1$:
$$R'_0 \oplus \lambda R'_i = (o'_0 \oplus \lambda o'_i) \oplus (c_0 \oplus \lambda c_i) g'$$

When $\lambda = c_0 \cdot c_i^{-1} \in \mathbb{F}_{16}^*$, the $g'$ term cancels completely:
$$c_0 \oplus \lambda c_i = 0 \implies R'_0 \oplus \lambda R'_i = o'_0 \oplus \lambda o'_i \in \mathcal{O}'$$

### 4. Recovering the Oil Subspace $\mathcal{O}'$

Since $\lambda \in \mathbb{F}_{16}^*$ has only 15 candidate non-zero values:
For each report $R'_i$ ($i = 1, \dots, 63$), we test all $\lambda \in \{1, \dots, 15\}$ and check if:
$$P'_k(R'_0 \oplus \lambda R'_i) = 0 \quad \text{for all } k \in \{0, \dots, 71\}$$

The unique matching $\lambda$ yields a non-zero vector $u_i = R'_0 \oplus \lambda R'_i \in \mathcal{O}'$.

Collecting these vectors across all $i = 1 \dots 63$ gives 63 vectors in $\mathcal{O}'$. Applying Gaussian elimination (row reduction over $\mathbb{F}_{16}$) recovers the exact 24-dimensional canonical basis (RREF) of $\mathcal{O}'$.

### 5. Key Derivation and Flag Decryption

The key generation in `mario.py` is:
```python
material = bytes(x for row in row_reduce(public_oil_basis) for x in row)
key = HKDF(material, 32, salt, SHA256, context=b"MARIO")
```
Because the Reduced Row Echelon Form (RREF) of a linear subspace is unique regardless of which basis is reduced, our recovered basis produces the exact same `material` bytes.

Deriving the key via HKDF and decrypting the AES-GCM ciphertext reveals the flag.

---

## Exploit Script

```python
#!/usr/bin/env python3
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

MOD_POLY = 0x13
MUL = [[0] * 16 for _ in range(16)]

def gf_mul(a, b):
	out = 0
	x = a
	y = b
	while y:
		if y & 1:
			out ^= x
		y >>= 1
		x <<= 1
		if x & 0x10:
			x ^= MOD_POLY
		x &= 0xF
	return out

for _a in range(16):
	for _b in range(16):
		MUL[_a][_b] = gf_mul(_a, _b)

def gf_pow(a, e):
	out = 1
	base = a
	exp = e
	while exp:
		if exp & 1:
			out = MUL[out][base]
		base = MUL[base][base]
		exp >>= 1
	return out

def gf_inv(a):
	if a == 0:
		raise ZeroDivisionError("inverse of zero")
	return gf_pow(a, 14)

def vec_scale(vec, scalar):
	row = MUL[scalar]
	return [row[x] for x in vec]

def vec_add(a, b):
	return [x ^ y for x, y in zip(a, b)]

def mat_copy(rows):
	return [row[:] for row in rows]

def row_reduce(rows):
	mat = mat_copy(rows)
	if not mat:
		return []
	cols = len(mat[0])
	rix = 0
	for cix in range(cols):
		pivot = None
		for row in range(rix, len(mat)):
			if mat[row][cix]:
				pivot = row
				break
		if pivot is None:
			continue
		mat[rix], mat[pivot] = mat[pivot], mat[rix]
		inv = gf_inv(mat[rix][cix])
		mat[rix] = vec_scale(mat[rix], inv)
		for row in range(len(mat)):
			if row != rix and mat[row][cix]:
				mat[row] = vec_add(mat[row], vec_scale(mat[rix], mat[row][cix]))
		rix += 1
		if rix == len(mat):
			break
	return [row for row in mat if any(row)]

def unpack_poly(s, n):
	poly = [[0] * n for _ in range(n)]
	idx = 0
	for i in range(n):
		for j in range(i, n):
			poly[i][j] = int(s[idx], 16)
			idx += 1
	return poly

def eval_quad(poly, x, n):
	out = 0
	for i in range(n):
		xi = x[i]
		if not xi:
			continue
		for j in range(i, n):
			cij = poly[i][j]
			if cij and x[j]:
				out ^= MUL[cij][MUL[xi][x[j]]]
	return out

def main():
	data = json.loads(Path("output.txt").read_text())
	n, m, d, s = data["p"]
	A = [unpack_poly(p_str, n) for p_str in data["A"]]
	B = data["B"]
	salt_hex, nonce_hex, ciphertext_hex = data["C"]

	salt = bytes.fromhex(salt_hex)
	nonce = bytes.fromhex(nonce_hex)
	ciphertext = bytes.fromhex(ciphertext_hex)

	# Eliminate secret vector g' by finding scalar multipliers lambda
	oil_vectors = []
	for i in range(1, len(B)):
		valid_lambdas = []
		for lam in range(1, 16):
			candidate = vec_add(B[0], vec_scale(B[i], lam))
			if all(eval_quad(poly, candidate, n) == 0 for poly in A):
				valid_lambdas.append(lam)
		if len(valid_lambdas) == 1:
			oil_vectors.append(vec_add(B[0], vec_scale(B[i], valid_lambdas[0])))

	# Compute canonical RREF basis
	rref_oil = row_reduce(oil_vectors)
	assert len(rref_oil) == d

	# Derive AES key and decrypt
	material = bytes(x for row in rref_oil for x in row)
	key = HKDF(material, 32, salt, SHA256, context=b"MARIO")

	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	cipher.update(b"MARIO")
	plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
	print("Flag:", plaintext.decode())

if __name__ == "__main__":
	main()
```

---

## Flag

```text
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```
