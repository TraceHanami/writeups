# Tollgate — Go ELF Binary Reverse Engineering & AES-CBC Protection

**Category:** Reverse Engineering  
**CTF Event:** Unknown CTF (Consolidated under Unknown)  
**Artifacts:**
- `tollgate` (1,454,232 bytes ELF 64-bit statically linked stripped Go executable)  
**Status:** In-Progress / Static Analysis  

---

## 1. Challenge Overview

"Tollgate" is a statically compiled, stripped 64-bit ELF binary written in the Go programming language (Go 1.21+ runtime). When run, it prompts the user for an access authorization key or toll pass to proceed through an automated checkpoint.

---

## 2. Static Analysis & Go Internals

Because standard Go binaries contain significant runtime metadata even when stripped of standard ELF symbol tables (`.symtab`), function boundaries and package structures can be reconstructed through Go's internal runtime data structures:

### A. Go Function Recovery via `pclntab`
Scanning the binary's `pclntab` (PC-Line Table) identifies the user-level package and function names:
- `tollgate/main.go`
- `main.main`: Top-level application coordinator; handles CLI arguments and terminal I/O.
- `main.check`: Validation predicate for the user-supplied license key / toll token.
- `main.unlock`: Success branch; initializes the cryptographic decryption routine.

### B. Cryptographic Subsystem
Strings and cross-references in `tollgate` indicate standard Go cryptography packages:
- `crypto/aes.expandKeyGo` / `crypto/aes.expandKeyAsm`: AES key expansion supporting 128, 192, or 256-bit keys.
- `crypto/cipher.NewCBCDecrypter`: AES in Cipher Block Chaining (CBC) mode.
- Assertion checks: `cipher.NewCBCDecrypter: IV length must equal block size`.

---

## 3. Reverse Engineering Strategy

1. **GDB / Delve Headless Inspection:** Set a breakpoint at `main.check` to inspect input parameter registers (`RAX`, `RBX` under the Go register-based ABI).
2. **Reversing `main.check`:** Determine whether the input is verified against a fixed SHA-256 hash or transformed via an arithmetic check.
3. **Decryption Extraction:** Once `main.check` returns boolean `1`, `main.unlock` derives the 16-byte AES key and 16-byte IV, calling `CBCDecrypter` on an embedded ciphertext buffer located in the `.rodata` section.
4. **Offline Decryption:** Extract the ciphertext and key from `.rodata` to decrypt the final flag string offline.
