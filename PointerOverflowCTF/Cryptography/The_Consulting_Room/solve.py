#!/usr/bin/env python3
"""
CBC Padding Oracle Attack — CRYP 200 "The Consulting Room"

Target: POST /challenges/consulting-room/oracle
Auth:   Bearer <API_TOKEN>
Body:   {"record": "<hex>"}
Resp:   {"padding": "valid"|"invalid"}

Classic Vaudenay-style attack: for each ciphertext block C[i], we control
the preceding 16 bytes sent to the oracle. By trying all 256 values for
each byte position (right to left) and watching for a "valid" padding
response, we recover the intermediate value I[i] = D_k(C[i]), and then
XOR with the REAL previous ciphertext block to get the real plaintext.

Usage:
    1. Set BASE_URL to the challenge host (fill in — depends on your
       CTF instance, e.g. https://<ctf-host>/challenges/consulting-room/oracle)
    2. Run: python3 padding_oracle.py
"""

import time
import requests

# ---- CONFIGURE THIS ----
BASE_URL = "https://pointeroverflowctf.com/challenges/consulting-room/oracle"
API_TOKEN = "tFPE6hYwuNo7CkLkhYtkNcXDETILe1qX"
ENCRYPTED_RECORD_HEX = (
    "179dace30221016c0813cf10f377e600273175fdc3d0ececbeb8f4cd0ec27bee"
    "40fdbff5f5bc6218515b1b8913a8ac01b8bc0a74972a2eb209f9ed910b057602e"
    "ca4010544eee556234aff8e58105b4e"
)
BLOCK_SIZE = 16
# -------------------------

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
})


def oracle_query(blob_bytes: bytes) -> bool:
    """
    Return True if the server reports padding as valid for this blob.

    NOTE: this server encodes the oracle signal in BOTH the JSON body
    ({"padding": "valid"|"invalid"}) AND the HTTP status code itself
    (200 for valid, 400 for invalid). We must NOT treat 400 as a hard
    error -- it's a legitimate (and expected, mostly "invalid") oracle
    response. Only truly unexpected statuses (401/403/404/5xx, or a
    missing "padding" key) should be treated as real errors.
    """
    r = session.post(BASE_URL, json={"record": blob_bytes.hex()}, timeout=10)

    if r.status_code == 429:
        retry_after = float(r.headers.get("Retry-After", 2))
        time.sleep(retry_after)
        return oracle_query(blob_bytes)  # retry once backoff elapses

    if r.status_code in (401, 403):
        raise RuntimeError(f"Auth error (HTTP {r.status_code}): {r.text!r}")
    if r.status_code == 404:
        raise RuntimeError(f"Endpoint not found (HTTP 404): check BASE_URL")
    if r.status_code >= 500:
        raise RuntimeError(f"Server error (HTTP {r.status_code}): {r.text!r}")

    try:
        data = r.json()
    except ValueError:
        raise RuntimeError(f"Non-JSON response (HTTP {r.status_code}): {r.text!r}")

    if "padding" not in data:
        raise RuntimeError(f"Unexpected response shape (HTTP {r.status_code}): {data!r}")

    return data.get("padding") == "valid"


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Recover the plaintext of target_block, given the ciphertext block
    immediately preceding it (prev_block), using the padding oracle.

    Returns the 16-byte plaintext (still PKCS#7-padded if it's the last block).
    """
    intermediate = bytearray(BLOCK_SIZE)   # I[i] = D_k(target_block)
    plaintext = bytearray(BLOCK_SIZE)

    for pad_val in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad_val  # byte index we're solving, right to left

        # Build a forged "previous block" we fully control.
        forged = bytearray(BLOCK_SIZE)
        # For already-solved bytes (to the right of pos), set them so that
        # decrypting XOR forged gives pad_val at those positions.
        for k in range(pos + 1, BLOCK_SIZE):
            forged[k] = intermediate[k] ^ pad_val

        found = False
        for guess in range(256):
            # Skip the trivial case on the first byte (pad_val=1) where the
            # unmodified real ciphertext might itself produce valid padding
            # due to a longer padding run — standard mitigation:
            if pad_val == 1 and guess == prev_block[pos]:
                pass  # still try it, but we'll disambiguate below if needed

            forged[pos] = guess
            test_blob = bytes(forged) + target_block

            if oracle_query(test_blob):
                # Candidate intermediate byte
                cand_I = guess ^ pad_val

                if pad_val == 1:
                    # Disambiguate: could be a genuine 0x01 pad, or an
                    # accidental longer padding (e.g. 0x02 0x02) triggered
                    # by chance. Verify by flipping the second-to-last byte
                    # and confirming padding is still reported valid.
                    forged2 = bytearray(forged)
                    forged2[pos - 1] ^= 0xFF  # corrupt the byte just before
                    test_blob2 = bytes(forged2) + target_block
                    if not oracle_query(test_blob2):
                        # False positive from longer padding; keep searching
                        continue

                intermediate[pos] = cand_I
                plaintext[pos] = cand_I ^ prev_block[pos]
                found = True
                print(f"    byte pos {pos:2d} (pad {pad_val:2d}): "
                      f"plaintext byte = {plaintext[pos]:#04x} ({chr(plaintext[pos]) if 32 <= plaintext[pos] < 127 else '.'!r})")
                break

        if not found:
            raise RuntimeError(
                f"No valid padding byte found at position {pos} "
                f"(pad_val={pad_val}) — check oracle connectivity/logic."
            )

    return bytes(plaintext)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        # Not valid padding — return as-is for inspection
        return data
    return data[:-pad_len]


def main():
    raw = bytes.fromhex(ENCRYPTED_RECORD_HEX)
    blocks = split_blocks(raw)

    if len(blocks) < 2:
        raise ValueError("Need at least IV + 1 ciphertext block.")

    print(f"[*] Total blocks (incl. IV): {len(blocks)}")

    # Sanity check: query the oracle with the untouched original record first.
    # This confirms the endpoint/auth/format are correct before we start
    # sending forged partial blobs.
    print("[*] Sanity check: querying oracle with the original, full record...")
    try:
        ok = oracle_query(raw)
        print(f"    -> padding reported: {'valid' if ok else 'invalid'}")
    except Exception as e:
        print(f"    -> sanity check failed: {e}")
        print("    (If this also 400s, the issue is auth/format, not blob length.)")

    # Sanity check 2: try a forged 2-block (32-byte) blob built from the
    # LAST real IV+block1 pair, unmodified, to see if partial-length blobs
    # are even accepted by this oracle.
    print("[*] Sanity check: querying oracle with an unmodified 2-block (32B) slice...")
    try:
        ok2 = oracle_query(blocks[0] + blocks[1])
        print(f"    -> padding reported: {'valid' if ok2 else 'invalid'}")
    except Exception as e:
        print(f"    -> 2-block slice failed: {e}")
        print("    (Oracle may require the FULL-length record on every call.)")

    recovered_plaintext = b""
    # blocks[0] is the IV; blocks[1:] are ciphertext blocks
    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        target_block = blocks[i]
        print(f"[*] Attacking block {i}/{len(blocks) - 1} ...")
        pt_block = attack_block(prev_block, target_block)
        recovered_plaintext += pt_block
        print(f"    -> {pt_block!r}")

    final = pkcs7_unpad(recovered_plaintext)
    print("\n[+] Recovered plaintext (padding stripped):")
    print(final.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
