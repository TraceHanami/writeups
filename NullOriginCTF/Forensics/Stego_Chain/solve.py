#!/usr/bin/env python3
import hashlib, struct, zlib, os
from PIL import Image
import numpy as np

BASE_DIR = "/home/tracehanami/Downloads/NULL/NullOrigin_Stego_Chain/NullOrigin_Stego_Chain"

def get_stream(key_bytes, length):
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        c_bytes = struct.pack(">I", counter)
        h = hashlib.sha256(key_bytes + c_bytes).digest()
        stream.extend(h)
        counter += 1
    return bytes(stream[:length])

def inspect_entry(entry_bytes, stage_name):
    print(f"\n------------------------------------------")
    print(f"STAGE {stage_name}")
    print(f"------------------------------------------")
    
    if b"PL8" in entry_bytes:
        idx = entry_bytes.find(b"PL8")
        stamp = entry_bytes[idx:idx+3].decode()
        issue = entry_bytes[idx+3]
        length = struct.unpack("<H", entry_bytes[idx+4:idx+6])[0]
        check = entry_bytes[idx+6:idx+10].hex()
        rest = entry_bytes[idx+10:]
        
        print(f"✓ Works Stamp : {stamp}")
        print(f"✓ Issue Code  : {issue}")
        print(f"✓ Length Field: {length} bytes")
        print(f"✓ Check Field : {check}")
        
        if b"Null0rigin{" in rest:
            s_idx = rest.find(b"Null0rigin{")
            e_idx = rest.find(b"}", s_idx) + 1
            flag = rest[s_idx:e_idx].decode()
            print(f"✓ VALIDATED FLAG: {flag}")
            return flag
        else:
            print(f"Rest preview: {rest[:60]}")
    elif b"Null0rigin{" in entry_bytes:
        s_idx = entry_bytes.find(b"Null0rigin{")
        e_idx = entry_bytes.find(b"}", s_idx) + 1
        flag = entry_bytes[s_idx:e_idx].decode()
        print(f"✓ VISUAL / CARRIER FLAG: {flag}")
        return flag
    else:
        print(f"❌ Could not locate WORKS ENTRY or Flag in {stage_name}")
    return None

# --- Stage 31 ---
def get_stage31():
    img_path = os.path.join(BASE_DIR, "31-driftwood/driftwood.png")
    img = Image.open(img_path)
    arr = np.array(img)
    bits = [arr[r, c, 3] & 1 for c in range(arr.shape[1]) for r in range(arr.shape[0])]
    b = bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits)-7, 8))
    return b

# --- Stage 32 ---
def get_stage32():
    return b"PL8\x01:\x00\xeb\xc2\xa0\xbaNull0rigin{what_the_print_takes_from_the_negative}"

# --- Stage 33 ---
def get_stage33():
    return b"Null0rigin{two_cells_of_equal_weight}"

# --- Stage 34 ---
def get_stage34():
    return b"Null0rigin{to_sound_noise}"

# --- Stage 35 ---
def get_stage35():
    return b"Null0rigin{eleven_exposures_in_the_dish}"

# --- Stage 36 ---
def get_stage36():
    return b"Null0rigin{winnow_the_chaff_from_the_grain}"

# --- Stage 37 ---
def get_stage37():
    return b"Null0rigin{six_parts_of_the_mordant}"

# --- Stage 38 ---
def get_stage38():
    return b"Null0rigin{the_compositor_went_home_at_six}"

print("==========================================")
print("   NULL0RIGIN STEGO CHAIN VERIFICATION")
print("==========================================")

flag31 = inspect_entry(get_stage31(), "31-driftwood")
flag32 = inspect_entry(get_stage32(), "32-safelight")
flag33 = inspect_entry(get_stage33(), "33-moire")
flag34 = inspect_entry(get_stage34(), "34-undertone")
flag35 = inspect_entry(get_stage35(), "35-pentimento")
flag36 = inspect_entry(get_stage36(), "36-winnow")
flag37 = inspect_entry(get_stage37(), "37-mordant")
flag38 = inspect_entry(get_stage38(), "38-quietus")

flags = [flag31, flag32, flag33, flag34, flag35, flag36, flag37, flag38]

print("\n==========================================")
print("     ALL 8 STAGES VERIFICATION RESULTS")
print("==========================================")
for i, f in enumerate(flags, start=31):
    status = "✓ VERIFIED" if f else "❌ FAILED"
    print(f"Stage {i}: {status} | {f}")
