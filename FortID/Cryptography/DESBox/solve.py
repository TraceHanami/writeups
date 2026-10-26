#!/usr/bin/env python3
"""
DESBox CTF Solver
=================

Vulnerability Analysis:
1. Random Permutation Bypass:
   load_key(user_key) shuffles the 24 bytes of user_key randomly.
   By choosing user_key = bytes([v] * 24), all 24 bytes are identical,
   making permute(user_key) deterministic regardless of RNG output.

2. DES Complementation Property:
   DES and 3DES satisfy the complementation property:
     D_{~K}(~C) = ~D_K(C)
   where ~X denotes bitwise complement (X ^ 0xFF).

3. Validation Bypass:
   - Call 1: Key A = 0x00 * 24, Key B = 0x02 * 24.
     Server encrypts FLAG under Key_A (effective byte 0x00): C_flag = E_{K_A}(FLAG).
   - Call 2: Key A = 0x02 * 24, Key B = 0xFE * 24.
     Key_B has effective key byte 0xFE, which is the exact bitwise complement of 0x00.
     Therefore, Key_B = ~Key_A.
     All checks in read_keys() pass because (0x02, 0xFE) are not effective complements of each other.

4. Flag Recovery:
   Sending ~C_flag to the debug ciphertext oracle under Key_B yields:
     Debug Output = D_{Key_B}(~C_flag) = D_{~Key_A}(~C_flag) = ~FLAG
   Complementing the Debug Output recovers the unencrypted FLAG.
"""

import sys
import subprocess

def solve_local(script_path='DESBox.py'):
    p = subprocess.Popen(
        [sys.executable, '-u', script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    def read_until(prompt):
        out = ""
        while prompt not in out:
            char = p.stdout.read(1)
            if not char:
                break
            out += char
        return out

    # 1. Read initial prompt
    read_until("C:\\> ")
    
    # 2. First KEYB invocation
    p.stdin.write("KEYB\n")
    p.stdin.flush()
    
    read_until("KEY A> ")
    p.stdin.write("00" * 24 + "\n")
    p.stdin.flush()

    read_until("KEY B> ")
    p.stdin.write("02" * 24 + "\n")
    p.stdin.flush()

    # Read output with encrypted FLAG under Key A (0x00)
    out = read_until("Debug ciphertext> ")

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    ct_flag_hex = None
    for i, line in enumerate(lines):
        if "encrypted under Key A:" in line:
            ct_flag_hex = lines[i+1]
            break

    print(f"[+] Encrypted FLAG (Key A = 0x00): {ct_flag_hex}")

    # Send dummy ciphertext for Call 1
    p.stdin.write("0000000000000000\n")
    p.stdin.flush()

    read_until("C:\\> ")

    # 3. Second KEYB invocation
    p.stdin.write("KEYB\n")
    p.stdin.flush()

    read_until("KEY A> ")
    p.stdin.write("02" * 24 + "\n")
    p.stdin.flush()

    read_until("KEY B> ")
    p.stdin.write("fe" * 24 + "\n")
    p.stdin.flush()

    read_until("Debug ciphertext> ")

    # Compute ~C_flag
    ct_flag_bytes = bytes.fromhex(ct_flag_hex)
    ct_comp_bytes = bytes(b ^ 0xFF for b in ct_flag_bytes)
    ct_comp_hex = ct_comp_bytes.hex()

    print(f"[+] Sending Complemented Ciphertext (~C_flag): {ct_comp_hex}")

    p.stdin.write(f"{ct_comp_hex}\n")
    p.stdin.flush()

    out = read_until("C:\\> ")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    debug_output_hex = None
    for i, line in enumerate(lines):
        if "Debug output:" in line:
            debug_output_hex = lines[i+1]
            break

    print(f"[+] Debug Output (~FLAG): {debug_output_hex}")

    debug_output_bytes = bytes.fromhex(debug_output_hex)
    flag_bytes = bytes(b ^ 0xFF for b in debug_output_bytes)

    print(f"\n[★] RECOVERED FLAG: {flag_bytes.decode(errors='ignore')}")

    p.stdin.write("EXIT\n")
    p.stdin.flush()
    p.wait()

if __name__ == "__main__":
    solve_local()
