# Hackel – Writeup

## Challenge Overview

The challenge presents a menu-driven service called **Hackel Security Service v1.0**. At first glance, the source code appears to implement a complicated permutation-group based cryptosystem involving:

* Permutations
* Group relations
* Homomorphic operations
* Generator validation
* Symmetric group checks

However, the actual vulnerability lies in the implementation of the training samples and encrypted flag encoding.

---

## Source Code Analysis

Inside `init_state()` the challenge generates training words:

```python
zero_words = [(t0,) * rng.randint(1, 9) for _ in range(16)]

one_words = [
    (t0,) * rng.randint(0, 9) + (t1,)
    for _ in range(16)
]
```

With default symbols:

```python
t0 = 'a'
t1 = 'b'
```

This means:

### Encoding of 0

```text
a
aa
aaa
aaaa
...
```

A word containing only `a` characters represents binary **0**.

### Encoding of 1

```text
b
ab
aab
aaab
...
```

A word ending in `b` represents binary **1**.

---

## Flag Encoding

The encrypted flag is generated as:

```python
flag_bits = "".join(
    f"{b:08b}"
    for b in flag_str.encode("utf-8")
)

flag_words = [
    (t0,) * rng.randint(1, 9)
    if bit == "0"
    else (t0,) * rng.randint(0, 9) + (t1,)
    for bit in flag_bits
]
```

Each bit of the flag is independently encoded.

Therefore:

| Word Pattern        | Bit |
| ------------------- | --- |
| Only `a` characters | 0   |
| Ends with `b`       | 1   |

The entire permutation-based cryptosystem becomes irrelevant.

---

## Speed Challenge Analysis

Option 5 displays:

```text
Challenge Words:
```

followed by 16 encoded words.

Example:

```text
a b aaaaaaaaab aaaab b aaaaaaab aa aaaaa
```

Classification rule:

```text
ends with 'b' -> 1
otherwise     -> 0
```

Applying the rule:

```text
a            -> 0
b            -> 1
aaaaaaaaab   -> 1
aaaab        -> 1
b            -> 1
aaaaaaab     -> 1
aa           -> 0
aaaaa        -> 0
```

Result:

```text
01111100...
```

---

## Automated Solver

```python
from pwn import *

io = remote("65.109.208.91", 3771)

io.recvuntil(b"> ")
io.sendline(b"5")

line = io.recvline_contains(b"Challenge Words:")
words = line.decode().split("Challenge Words: ")[1].split()

bits = "".join(
    "1" if w.endswith("b") else "0"
    for w in words
)

io.recvuntil(b"Your Classification Bits:")
io.sendline(bits.encode())

io.interactive()
```

The script answers instantly and avoids the 5-second timeout.

---

## Root Cause

The challenge intends to hide information behind a complex permutation-group construction, but the flag encoding leaks the plaintext bits directly through the structure of the generated words.

The encoding creates a deterministic distinction:

```text
0 -> a+
1 -> a*b
```

An attacker only needs to inspect the final character of each word to recover the corresponding bit.

---

## Conclusion

The cryptographic layer is unnecessary for solving the challenge. By observing that:

```text
word ends with b => 1
word contains only a => 0
```

the challenge reduces to a simple binary decoding problem. The speed challenge can be solved automatically with a short script, yielding the flag immediately after successful classification.
