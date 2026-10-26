# CREST CTF 2026 — Vault Key Derivation Function (KDF)

**Category:** Cryptography / Password Cracking  
**CTF Event:** CREST CTF 2026  
**Artifacts:**
- `files_BY9BpT1.zip` & `files_BY9BpT1(1).zip` (628,254 bytes)
- `player/vault.bin` (Encrypted vault storage)
- `player/kdf_spec.py` (Key derivation function specification)
- `player/password_constraints.txt` & `player/password_words.txt`
- `player/flag_candidates.txt` (Decoy verification list)
- `player/maintenance_scripts/` (Diagnostic automation scripts)  
**Status:** In-Progress / Cryptographic Reconstruction  

---

## 1. Challenge Overview

Participants are tasked with recovering the master passphrase protecting `vault.bin`. The system relies on a custom Key Derivation Function implemented in `kdf_spec.py` that processes user passwords adhering to constraints defined in `password_constraints.txt`.

---

## 2. Cryptographic Architecture

### A. Key Derivation (`kdf_spec.py`)
- Employs PBKDF2-HMAC-SHA256 with dynamic iteration counts.
- Salt is derived from vault header identifiers.
- A secondary permutation round applies byte shifts over derived keys before decrypting the AES-CBC container.

### B. Password Space Reduction
`password_constraints.txt` outlines structural rules restricting the valid candidate space:
- Wordlist base vocabulary: `password_words.txt`.
- Checksum validation: An archival reconciliation checksum mandates that word combinations produce a specific CRC32 / Adler32 residue.
- Decoy Elimination: `flag_candidates.txt` explicitly catalogs decoy flag tokens to be filtered out during brute-force testing.
