# Pointer Overflow CTF — CRYP 200: "The Consulting Room"

**Category:** Cryptography (Padding Oracle Attack)  
**CTF Event:** Pointer Overflow CTF 2026  
**Artifacts:**
- `padding_oracle.py` (7,931 bytes)  
**Status:** Solved  
**Target Endpoint:** `POST /challenges/consulting-room/oracle`

---

## 1. Challenge Overview

In "The Consulting Room" (CRYP 200), participants interact with a remote oracle endpoint that accepts an encrypted hex-encoded record and decrypts it using AES-CBC with PKCS#7 padding:
```http
POST /challenges/consulting-room/oracle HTTP/1.1
Authorization: Bearer <API_TOKEN>
Content-Type: application/json

{"record": "<hex_ciphertext>"}
```
The server responds with a boolean status indicating whether the PKCS#7 padding was valid or invalid:
```json
{"padding": "valid"}
```
or
```json
{"padding": "invalid"}
```

---

## 2. Vulnerability Analysis: Vaudenay CBC Padding Oracle

AES in Cipher Block Chaining (CBC) mode decrypts ciphertext block $C_i$ as:
$$P_i = D_K(C_i) \oplus C_{i-1}$$
where $C_0$ is the Initialization Vector (IV).

Under PKCS#7 padding, a block with $k$ padding bytes ends with $k$ copies of byte value $k$ (e.g. `\x01` for 1 byte, `\x02\x02` for 2 bytes).

Because the server reveals whether the padding is valid without revealing the plaintext, an attacker can determine the intermediate state $I_i = D_K(C_i)$ byte by byte, moving from the last byte to the first byte of each block:
1. For byte index $j = 15 \dots 0$, set the suffix of the forged preceding block $C'_{i-1}[k]$ ($k > j$) such that $C'_{i-1}[k] \oplus I_i[k] = \text{pad\_len}$.
2. Iterate through all 256 possible byte values for $C'_{i-1}[j]$.
3. When the oracle returns `valid`, the decrypted byte satisfies $D_K(C_i)[j] \oplus C'_{i-1}[j] = \text{pad\_len}$.
4. Compute $I_i[j] = C'_{i-1}[j] \oplus \text{pad\_len}$.
5. Recover the real plaintext byte: $P_i[j] = I_i[j] \oplus C_{i-1}[j]$.

---

## 3. Exploit Implementation (`padding_oracle.py`)

The exploit script automates this process across all blocks:
```python
def decrypt_block(oracle, c_prev, c_target):
    intermediate = bytearray(16)
    plaintext = bytearray(16)
    
    for byte_pos in range(15, -1, -1):
        pad_val = 16 - byte_pos
        prefix = bytearray(byte_pos)
        
        # Build forged block with desired padding on known suffix
        test_block = bytearray(16)
        for k in range(byte_pos + 1, 16):
            test_block[k] = intermediate[k] ^ pad_val
            
        found = False
        for guess in range(256):
            test_block[byte_pos] = guess
            if oracle.query(bytes(test_block) + c_target):
                intermediate[byte_pos] = guess ^ pad_val
                plaintext[byte_pos] = intermediate[byte_pos] ^ c_prev[byte_pos]
                found = True
                break
        if not found:
            raise RuntimeError(f"Failed to find valid padding byte at {byte_pos}")
            
    return bytes(plaintext)
```

Running `padding_oracle.py` against the challenge API successfully decrypts the ciphertext block by block, unpadding the recovered bytes to obtain the flag.
