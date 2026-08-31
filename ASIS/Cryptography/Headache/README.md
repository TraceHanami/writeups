# Headache — ASIS CTF Writeup

**Category:** Cryptography / Optimization / AI-Math  
**Target:** Non-Linear Hamiltonian Authenticator Oracle (H-PRF)  
**Flag:** `ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}`

---

## 1. Challenge Overview

We are given a remote server running an authentication oracle called **H-PRF** (`server.py`). The challenge requires passing **7 consecutive rounds**. In each round:
1. The server generates secret coupling tensors $A \in \mathbb{R}^{3 \times 4 \times 4}$ and observable vectors $B \in \mathbb{R}^{3 \times 4}$ with uniform random weights in $[0.5, 2.0]$.
2. We can submit query matrices $X \in \mathbb{R}^{L \times 4}$ (up to a budget of 1200 queries per round, with $1 \le L \le 20$).
3. The server computes a scalar tag:
   $$\text{tag}(X) = \sum_{c=0}^{2} \sum_{i=1}^{L} p_{c, i} \cdot (X_i \cdot B_c)$$
   where the softmax / Boltzmann weights $p_{c}$ are defined by:
   $$e_{c, i} = X_i^T A_c X_L$$
   $$p_{c, i} = \frac{\exp(e_{c, i} - \max_k e_{c, k})}{\sum_{j=1}^{L} \exp(e_{c, j} - \max_k e_{c, k})}$$
   ($X_L = X[-1]$ is the tail row of matrix $X$).
4. After querying, we send `challenge`. The server presents 6 random evaluation sequences of varying lengths ($L \in \{3, 5, 7, 9, 13, 17\}$) and expects us to forge the exact tags within an absolute tolerance of $\varepsilon = 10^{-6}$.

---

## 2. Mathematical Analysis

The tag function for each channel $c \in \{0, 1, 2\}$ is equivalent to a multi-channel self-attention layer with linear readouts:
- **Query / Key interaction:** bilinear form $e_c = X (A_c v)$, where $v = X[-1]$.
- **Softmax distribution:** $p_c = \text{softmax}(e_c) \in \mathbb{R}^L$.
- **Values / Observables:** $o_c = X B_c \in \mathbb{R}^L$.
- **Channel output:** $y_c = p_c^T o_c$.
- **Total output:** $y = \sum_{c=0}^{2} y_c$.

The total number of unknown parameters per round is:
- $3 \times 4 \times 4 = 48$ elements for $A$.
- $3 \times 4 = 12$ elements for $B$.
- **Total:** $48 + 12 = 60$ scalar parameters.

Because the forward map is smooth, differentiable, and has only 60 dimensions, recovering $A$ and $B$ from empirical input-output pairs $(X^{(k)}, y^{(k)})$ is an exact **Nonlinear Least Squares (NLLS)** parameter estimation problem.

---

## 3. Analytic Gradient & Jacobian Derivation

Given a loss residual for sample $k$:
$$r_k(\theta) = \hat{y}(X^{(k)}; A, B) - y^{(k)}$$

To enable fast Gauss-Newton / Levenberg-Marquardt convergence, we compute the exact analytic Jacobian:

### Softmax Derivative
For each channel $c$, let $y_c = \sum_i p_{c, i} o_{c, i}$.
The derivative of $y_c$ with respect to $e_{c, i}$ is:
$$\frac{\partial y_c}{\partial e_{c, i}} = p_{c, i}(o_{c, i} - y_c) \equiv s_{c, i}$$

### Gradients with respect to $A_c$ and $B_c$
Since $e_{c, i} = X_i^T A_c v$:
$$\frac{\partial y_c}{\partial A_c} = \sum_{i=1}^{L} s_{c, i} \cdot (X_i \otimes v) = (X^T s_c) \otimes v = (s_c^T X)^T v^T$$

Since $o_{c, i} = X_i^T B_c$:
$$\frac{\partial y_c}{\partial B_c} = \sum_{i=1}^{L} p_{c, i} X_i = X^T p_c$$

Thus, the Jacobian row for sample $k$ is formed by concatenating $\text{vec}\left(\frac{\partial y_c}{\partial A_c}\right)$ and $\frac{\partial y_c}{\partial B_c}$ across all 3 channels.

---

## 4. Optimization & Solver Engineering

To ensure execution speed, prevent server timeouts, and avoid local minima:
1. **Vectorized Jacobian:** Vectorized batch evaluations using `numpy` tensor operations (`np.matmul` and `np.einsum`) reduce Python overhead to a few milliseconds.
2. **Short Sequences for Condition Number:** Generating queries with lengths $L \in [2, 5]$ provides strong gradients without over-saturating softmax exponentials.
3. **Pipelined Batch Queries:** Sending queries in batches over a raw TCP socket avoids per-request network round-trip overhead.
4. **Levenberg-Marquardt with Multi-Start:** Running `scipy.optimize.least_squares` with method `'lm'` and multiple random restarts converges to near machine precision ($\text{cost} < 10^{-27}$, error $< 10^{-14}$) in $\le 5$ iterations.

---

## 5. Execution Results

```text
=== Non-Linear Hamiltonian Authenticator Oracle (H-PRF) ===
Dimension: 4, Rounds to pass: 7
Max queries per round: 1200, Max sequence length: 20
[*] Mining PoW: sha256(00da7be29e4c46d0+nonce) startswith '00000' ...
[*] Found nonce=7082018 in 6.40s
[*] {'status': 'pow_ok', 'message': 'Proof of work verified.'}

===== Round 1 =====
    total collected: 220 queries (7.1s elapsed)
[*] Fit done in 9.12s, final cost=2.502e-28
[*] {'status': 'ok', 'message': 'Round 1 authenticated! (max_err=3.55e-15)'}

===== Round 2 =====
    total collected: 220 queries (7.1s elapsed)
[*] Fit done in 0.24s, final cost=1.315e-28
[*] {'status': 'ok', 'message': 'Round 2 authenticated! (max_err=1.78e-15)'}

...

===== Round 7 =====
    total collected: 220 queries (7.1s elapsed)
[*] Fit done in 0.31s, final cost=1.793e-28
[*] {'status': 'ok', 'flag': 'ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}', 'message': 'All rounds authenticated! (max_err=1.78e-15)'}
```

Flag:
```
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```
