# Rewind — CTF Writeup

**Category:** Cryptography  
**Challenge:** Rewind  
**Event:** z0d1ak CTF  
**Service Endpoint:** `rewind-5686986fafaa.chals.z0d1ak.org:1337` (TLS/SSL)

---

## 1. Challenge Overview

Upon connecting to the service via `ncat --ssl rewind-5686986fafaa.chals.z0d1ak.org 1337`, the remote server greets the user with the following banner and options:

```text
 ____               _           _
|  _ \ _____      _(_)_ __   __| |
| |_) / _ \ \ /\ / / | '_ \ / _` |
|  _ <  __/\ V  V /| | | | | (_| |
|_| \_\___| \_/\_/ |_|_| |_|\__,_|


The operator swears the stream is fresh every time.
Watch what happens when the counter keeps rewinding.

secret_ct = 9d5bf0a08047677de4f4d3b08d7e11cc11d58d8c6cd39d2d464c73dd0898b6e126b975ebea5ef406adc1fac5

[1] Show encrypted token
[2] Encrypt attacker-controlled bytes (hex)
[3] Exit
> 
```

The menu provides three options:
1. `[1]` Show encrypted token (re-displays `secret_ct`).
2. `[2]` Encrypt attacker-controlled plaintext bytes (in hex).
3. `[3]` Exit.

---

## 2. Vulnerability Analysis

The challenge title ("Rewind") and hint:
> *"The operator swears the stream is fresh every time. Watch what happens when the counter keeps rewinding."*

point directly to a **keystream reuse vulnerability** (stream cipher / CTR mode nonce-counter reuse):

1. **Stream Cipher Operation:**
   In stream ciphers (or block ciphers in CTR mode), encryption of a plaintext $P$ with keystream $K$ is performed via bitwise XOR:
   $$C = P \oplus K$$

2. **Counter Rewind / Keystream Reuse:**
   The server encrypts `secret_ct` (the secret flag / token) using keystream $K$:
   $$\text{secret\_ct} = \text{FLAG} \oplus K$$
   When selecting option `[2]`, the encryption routine rewinds the counter and reuses the exact same keystream $K$ for user-supplied input $P_{\text{user}}$:
   $$C_{\text{user}} = P_{\text{user}} \oplus K$$

3. **Keystream Recovery via Chosen Plaintext Attack (CPA):**
   If we supply an all-zero plaintext $P_{\text{user}} = 0000\dots00$ of length matching `secret_ct`:
   $$C_{\text{zero}} = (0000\dots00) \oplus K = K$$
   The returned ciphertext is identical to the raw keystream $K$.

4. **Flag Decryption:**
   XORing the returned keystream $K$ with `secret_ct` completely decrypts the flag:
   $$\text{FLAG} = \text{secret\_ct} \oplus K$$

---

## 3. Exploit Script (`solve_rewind.py`)

```python
from pwn import *

# Connect to the remote challenge over TLS/SSL
r = remote('rewind-5686986fafaa.chals.z0d1ak.org', 1337, ssl=True)

# Parse the banner and secret ciphertext
banner = r.recvuntil(b'> ').decode()
secret_ct_line = [line for line in banner.splitlines() if 'secret_ct' in line][0]
secret_ct_hex = secret_ct_line.split('=')[1].strip()
secret_ct = bytes.fromhex(secret_ct_hex)

# Query option [2] with null bytes of the same length to leak the keystream
r.sendline(b'2')
r.recvuntil(b'hex plaintext > ')
r.sendline(b'00' * len(secret_ct))

resp = r.recvuntil(b'> ').decode()
ct_line = [line for line in resp.splitlines() if 'ct =' in line][0]
keystream_hex = ct_line.split('=')[1].strip()
keystream = bytes.fromhex(keystream_hex)

# Decrypt the secret ciphertext by XORing with the leaked keystream
flag = bytes([a ^ b for a, b in zip(secret_ct, keystream)])
print("Flag:", flag.decode())

r.close()
```

---

## 4. Execution & Flag

Running the solve script against the remote server:

```bash
$ python3 solve_rewind.py
[+] Opening connection to rewind-5686986fafaa.chals.z0d1ak.org on port 1337: Done
Flag: zdk{Rew1NdIN6_tH3_CoUN7Er_r3Us3S_ThE_5tREAm}
[*] Closed connection to rewind-5686986fafaa.chals.z0d1ak.org port 1337
```

**Flag:**
```text
zdk{Rew1NdIN6_tH3_CoUN7Er_r3Us3S_ThE_5tREAm}
```
