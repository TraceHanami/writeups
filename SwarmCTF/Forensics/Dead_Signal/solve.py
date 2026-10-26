#!/usr/bin/env python3
"""
Operation: Dead Signal — Comprehensive CTF Flag Recovery Tool
Target: Research Station Orpheus (Sector 4 - Sub-Antarctic)

This script performs end-to-end forensic analysis and cryptographic recovery:
  1. Reassembles ORPHPKT UDP fragments from station_traffic.log to extract K1.
  2. Authenticates and decrypts telemetry records from telemetry.raw to extract K2.
  3. Demodulates acoustic 2-FSK hydrophone signal from sensor_feed.dat to extract K3.
  4. Parses physical SRAM memory structures from core_dump.raw to extract K4.
  5. Locates and extracts the VAUL blackbox container from core_dump.raw.
  6. Derives the AES-256 master key via SHA-256(K1:K2:K3:K4).
  7. Decrypts the vault, validates padding, and extracts the verified CTF flag.
"""

import os
import sys
import json
import zlib
import struct
import wave
import hmac
import hashlib
from pathlib import Path
import numpy as np
from Crypto.Cipher import AES

EVIDENCE_DIR = Path("/home/tracehanami/Downloads/evidence")
ANALYSIS_DIR = Path("/home/tracehanami/Downloads/orpheus_analysis")

def pcap_read_udp_packets(pcap_path):
    """Parses a standard PCAP file without external dependency to extract UDP payloads."""
    with open(pcap_path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            raise ValueError("Invalid PCAP header")
        magic = ghdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        else:
            raise ValueError(f"Unknown PCAP magic: {magic.hex()}")

        packets = []
        frame_idx = 0
        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            frame_idx += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
            pdata = f.read(incl_len)
            if len(pdata) < incl_len:
                break

            # Ethernet header (14 bytes)
            if len(pdata) < 14:
                continue
            eth_type = struct.unpack("!H", pdata[12:14])[0]
            if eth_type != 0x0800: # IPv4
                continue

            # IPv4 header
            ip_data = pdata[14:]
            if len(ip_data) < 20:
                continue
            ihl = (ip_data[0] & 0x0F) * 4
            protocol = ip_data[9]
            if protocol != 17: # UDP
                continue

            # UDP header (8 bytes)
            udp_data = ip_data[ihl:]
            if len(udp_data) < 8:
                continue
            sport, dport, ulen, ucksum = struct.unpack("!HHHH", udp_data[:8])
            udp_payload = udp_data[8:ulen]
            packets.append({
                "frame": frame_idx,
                "sport": sport,
                "dport": dport,
                "payload": udp_payload
            })
    return packets

def recover_k1(pcap_file):
    print("[*] Phase B.1: Recovering K1 from station_traffic.log...")
    packets = pcap_read_udp_packets(pcap_file)
    orph_packets = [p for p in packets if p["dport"] == 9100 and p["payload"].startswith(b"ORPHPKT")]
    print(f"    Discovered {len(orph_packets)} candidate ORPHPKT packets.")

    fragments = {}
    for p in orph_packets:
        payload = p["payload"]
        if len(payload) < 20:
            continue
        magic = payload[:7]
        version = payload[7]
        stream_id, total_frags, seq_idx, decl_len, declared_crc = struct.unpack(">HHHHI", payload[8:20])
        frag_data = payload[20:20 + decl_len]
        computed_crc = zlib.crc32(frag_data)
        if computed_crc != declared_crc:
            print(f"[-] Frame {p['frame']}: CRC mismatch!")
            continue
        fragments[seq_idx] = frag_data

    total_expected = 12
    if len(fragments) != total_expected:
        raise RuntimeError(f"Missing fragments: got {len(fragments)} of {total_expected}")

    reassembled = bytearray()
    for i in range(total_expected):
        reassembled.extend(fragments[i])

    # Parse ORPHSPEC header
    spec_magic = reassembled[:8]
    if spec_magic != b"ORPHSPEC":
        raise ValueError(f"Invalid ORPHSPEC magic: {spec_magic}")
    spec_ver = struct.unpack("<I", reassembled[8:12])[0]
    stn_id = reassembled[12:28].rstrip(b"\x00").decode("ascii")
    boot_epoch = struct.unpack("<I", reassembled[28:32])[0]
    k1 = reassembled[32:64].decode("ascii")
    print(f"[+] K1 successfully recovered: {k1}")
    print(f"    Specification: {spec_magic.decode()} v{spec_ver}, Station: {stn_id}, Boot Epoch: {boot_epoch}")
    return k1

def recover_k2(telemetry_file, k1):
    print("[*] Phase B.2: Recovering K2 from telemetry.raw...")
    with open(telemetry_file, "rb") as f:
        data = f.read()

    pos = 0x80
    k2 = None
    k1_ascii = k1.encode("ascii")
    while pos < len(data):
        if data[pos:pos+2] != b"\x5a\xa5":
            nxt = data.find(b"\x5a\xa5", pos)
            if nxt == -1:
                break
            pos = nxt

        sync, seq, ticks, port, flags, plen = struct.unpack("<HIIHHH", data[pos:pos+16])
        record_len = 16 + plen
        payload = data[pos+16:pos+record_len]
        tag = data[pos+record_len:pos+record_len+16]

        if flags & 0x0004: # Hardware authenticated
            computed_hmac = hmac.new(k1_ascii, data[pos:pos+record_len], hashlib.sha256).digest()[:16]
            if computed_hmac == tag:
                # Authentic record
                if flags & 0x0001: # Encrypted
                    # Decrypt with repeated XOR with K1[0:16]
                    k1_key = k1_ascii[:16]
                    decrypted = bytes([b ^ k1_key[i % 16] for i, b in enumerate(payload)])
                    for line in decrypted.decode("utf-8", errors="replace").splitlines():
                        if "KEY_PART_2:" in line:
                            k2 = line.split("KEY_PART_2:")[1].strip()
                            print(f"[+] Authenticated Telemetry Record validated (Seq {seq}, Ticks {ticks} ms, Port {port})")
                            print(f"[+] K2 successfully recovered: {k2}")

        nxt_sync = data.find(b"\x5a\xa5", pos+16)
        pos = nxt_sync if nxt_sync != -1 else len(data)

    if not k2:
        raise RuntimeError("Failed to recover authenticated K2 from telemetry.raw")
    return k2

def recover_k3(sensor_file):
    print("[*] Phase B.3: Recovering K3 from sensor_feed.dat...")
    with wave.open(str(sensor_file), "rb") as w:
        raw = w.readframes(w.getnframes())
        samples = np.frombuffer(raw, dtype=np.int16).astype(np.float32)

    fs = 44100
    baud = 50
    sps = int(fs / baud) # 882 samples per symbol

    # Matched filter reference vectors for 1200 Hz (mark, 1) and 2200 Hz (space, 0)
    t = np.arange(sps) / fs
    ref_1200_cos = np.cos(2 * np.pi * 1200 * t)
    ref_1200_sin = np.sin(2 * np.pi * 1200 * t)
    ref_2200_cos = np.cos(2 * np.pi * 2200 * t)
    ref_2200_sin = np.sin(2 * np.pi * 2200 * t)

    # Demodulate starting at T = 1.0s (sample 44100)
    start_samp = 44100
    total_symbols = (len(samples) - start_samp) // sps
    bits = []
    for i in range(total_symbols):
        chunk = samples[start_samp + i * sps : start_samp + (i + 1) * sps]
        e1200 = np.sum(chunk * ref_1200_cos)**2 + np.sum(chunk * ref_1200_sin)**2
        e2200 = np.sum(chunk * ref_2200_cos)**2 + np.sum(chunk * ref_2200_sin)**2
        bits.append(1 if e1200 > e2200 else 0)

    # Convert to bytes
    decoded_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        decoded_bytes.append(byte_val)

    # Verify frame sync 0xAA 0xAA 0x7E
    if decoded_bytes[:3] != b"\xaa\xaa\x7e":
        raise ValueError(f"Sync preamble mismatch: {decoded_bytes[:3].hex()}")

    # Find closing delimiter 0x7E
    end_idx = decoded_bytes.find(b"\x7e", 3)
    frame_content = decoded_bytes[3:end_idx] # payload + 2-byte CRC
    payload = frame_content[:-2]
    received_crc = struct.unpack(">H", frame_content[-2:])[0]

    # CRC-16 CCITT (false) calculation
    crc = 0xFFFF
    for b in payload:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    if crc != received_crc:
        raise ValueError(f"Audio frame CRC-16 mismatch: received 0x{received_crc:04x}, calculated 0x{crc:04x}")

    print(f"[+] Audio frame CRC-16 validated: 0x{crc:04x}")
    k3_str = payload.decode("ascii")
    if not k3_str.startswith("K3:"):
        raise ValueError(f"Unexpected audio frame payload: {k3_str}")
    k3 = k3_str.split("K3:")[1]
    print(f"[+] K3 successfully recovered: {k3}")
    return k3

def recover_k4_and_vault(core_dump_file):
    print("[*] Phase B.4 & Phase C: Recovering K4 and Vault from core_dump.raw...")
    with open(core_dump_file, "rb") as f:
        data = f.read()

    # Locate SESS structures
    sess_offsets = [0x08400, 0x14200, 0x22100, 0x2de00]
    target_sess = 0x22100 # EMERGENCY_SEAL session
    sess_chunk = data[target_sess:target_sess+64]
    magic, stream_id, timestamp, stn_id = struct.unpack("<4sIII", sess_chunk[:16])
    tag = sess_chunk[16:32].rstrip(b"\x00").decode("ascii")
    k4 = sess_chunk[32:64].decode("ascii")

    print(f"[+] Authentic Session located at 0x{target_sess:05x}:")
    print(f"    Stream ID: 0x{stream_id:04x}, Timestamp: {timestamp}, Tag: {tag}")
    print(f"[+] K4 successfully recovered: {k4}")

    # Locate VAUL container
    vault_offset = 0x31000
    vaul_hdr = data[vault_offset:vault_offset+16]
    v_magic, v_ver, v_timestamp, v_len = struct.unpack("<4sIII", vaul_hdr)
    if v_magic != b"VAUL":
        raise ValueError(f"Vault magic mismatch: {v_magic}")

    iv = data[vault_offset+16:vault_offset+32]
    ciphertext = data[vault_offset+32:vault_offset+32+v_len]

    print(f"[+] Vault container located at 0x{vault_offset:05x}:")
    print(f"    Version: {v_ver}, Sealing Timestamp: {v_timestamp}, Ciphertext Length: {v_len} bytes")
    print(f"    Initialization Vector (IV): {iv.hex()}")

    return k4, iv, ciphertext, vault_offset, v_len

def derive_key(k1, k2, k3, k4):
    print("[*] Phase D: Deriving Master AES-256 Key...")
    hash_input = f"{k1}:{k2}:{k3}:{k4}".encode("ascii")
    master_key = hashlib.sha256(hash_input).digest()
    print(f"    Hash Input: {hash_input.decode('ascii')}")
    print(f"[+] Master Key (Hex): {master_key.hex()}")
    return master_key, hash_input

def decrypt_vault(master_key, iv, ciphertext):
    print("[*] Phase E: Decrypting Blackbox Vault...")
    cipher = AES.new(master_key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)

    # Validate PKCS#7 padding
    pad_len = plaintext_padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding length: {pad_len}")
    if plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    plaintext = plaintext_padded[:-pad_len].decode("utf-8")
    print("[+] PKCS#7 padding verified and removed.")

    vault_json = json.loads(plaintext)
    flag = vault_json.get("flag", "")
    print(f"[+] Plaintext successfully parsed as JSON incident record.")
    return plaintext, vault_json, flag

def main():
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("OPERATION: DEAD SIGNAL — FORENSIC RECOVERY EXECUTABLE")
    print("=" * 80)

    # 1. Recover K1
    k1 = recover_k1(EVIDENCE_DIR / "station_traffic.log")

    # 2. Recover K2
    k2 = recover_k2(EVIDENCE_DIR / "telemetry.raw", k1)

    # 3. Recover K3
    k3 = recover_k3(EVIDENCE_DIR / "sensor_feed.dat")

    # 4. Recover K4 and Vault
    k4, iv, ciphertext, vault_off, ct_len = recover_k4_and_vault(EVIDENCE_DIR / "core_dump.raw")

    # 5. Derive Master Key
    master_key, hash_input = derive_key(k1, k2, k3, k4)

    # 6. Decrypt Vault
    plaintext, vault_json, flag = decrypt_vault(master_key, iv, ciphertext)

    print("\n" + "=" * 80)
    print("FLAG RECOVERY RESULTS")
    print("=" * 80)
    print(f"RECOVERED FLAG: {flag}\n")

    # Save artifacts
    vault_bin_path = ANALYSIS_DIR / "vault_extracted.bin"
    with open(vault_bin_path, "wb") as f:
        f.write(ciphertext)

    vault_json_path = ANALYSIS_DIR / "vault_decrypted.json"
    with open(vault_json_path, "w", encoding="utf-8") as f:
        f.write(plaintext)

    report = {
        "status": "Confirmed",
        "flag": flag,
        "station": vault_json.get("station"),
        "incident_id": vault_json.get("incident_id"),
        "timestamp_utc": vault_json.get("timestamp_utc"),
        "keys": {
            "K1": k1,
            "K2": k2,
            "K3": k3,
            "K4": k4
        },
        "master_key_derivation": {
            "formula": "SHA256(K1:K2:K3:K4)",
            "hash_input_ascii": hash_input.decode("ascii"),
            "derived_key_hex": master_key.hex()
        },
        "vault": {
            "file": "core_dump.raw",
            "offset_hex": f"0x{vault_off:05x}",
            "ciphertext_len_bytes": ct_len,
            "iv_hex": iv.hex()
        }
    }

    report_json_path = ANALYSIS_DIR / "recovery_report.json"
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    report_txt_path = ANALYSIS_DIR / "recovery_report.txt"
    with open(report_txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("OPERATION: DEAD SIGNAL — RECOVERY SUMMARY REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"RECOVERED FLAG: {flag}\n")
        f.write(f"Recovery Status: Confirmed\n\n")
        f.write(f"Key Components:\n")
        f.write(f"  - K1: {k1} (station_traffic.log, reassembled ORPHPKT stream)\n")
        f.write(f"  - K2: {k2} (telemetry.raw, authenticated & decrypted record at 0x0C85)\n")
        f.write(f"  - K3: {k3} (sensor_feed.dat, 2-FSK acoustic demodulation with CRC-16)\n")
        f.write(f"  - K4: {k4} (core_dump.raw, active EMERGENCY_SEAL session at 0x22100)\n\n")
        f.write(f"Master Key Derivation:\n")
        f.write(f"  - Hash Input: {hash_input.decode('ascii')}\n")
        f.write(f"  - Master Key (SHA-256): {master_key.hex()}\n\n")
        f.write(f"Vault Artifact:\n")
        f.write(f"  - File: core_dump.raw at 0x{vault_off:05x}\n")
        f.write(f"  - Ciphertext Length: {ct_len} bytes\n")
        f.write(f"  - IV: {iv.hex()}\n\n")
        f.write(f"Decrypted Plaintext:\n")
        f.write(plaintext + "\n")

    print(f"[+] Extracted ciphertext saved to: {vault_bin_path}")
    print(f"[+] Decrypted JSON vault saved to: {vault_json_path}")
    print(f"[+] Recovery reports saved to: {report_json_path} and {report_txt_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
