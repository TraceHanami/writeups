# GhostVM — Reverse Engineering Writeup

## Metadata
- **Challenge Name:** GhostVM
- **CTF / Event:** CREST CTF 2026
- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Artifacts:**
  - Binary: `ghostvm` (ELF 64-bit LSB executable, x86-64, statically linked, stripped, 714,768 bytes)
- **Status:** Analyzed / In-Progress (Full VM Architecture Reconstructed)
- **Flag Format:** `CREST{...}`

---

## Challenge Overview
The `ghostvm` challenge provides a single stripped, statically linked 64-bit Linux ELF binary. When executed, it prompts the user with `ghost> ` and reads a string from standard input (up to 128 bytes). If the input satisfies the internal validation constraints, it prints `Access granted.`; otherwise, it emits `Nope.`.

Reverse engineering reveals a custom stack-based virtual machine implementing dynamic self-decrypting bytecode and anti-debugging logic.

---

## Binary Fingerprinting & Properties
- **File Format:** ELF 64-bit LSB executable, x86-64, statically linked
- **Build ID:** `8020a6813291028b049f14566a33faa795b8823c`
- **Stripped:** Yes (`nm` returns 0 symbols; section headers intact)
- **Entry Point:** `0x4019d0`
- **Main Function:** `0x401830`
- **Static Strings:**
  - Success message: `"Access granted."` at virtual address `0x480010`
  - Failure message: `"Nope."` at virtual address `0x480020`
  - Input prompt: `"ghost> "` at virtual address `0x480026`

---

## Static & Architectural Analysis

### 1. VM Dispatcher Initialization (`0x401830`)
In `main` (`0x401830`), the binary initializes a 256-entry opcode jump table in the BSS at `0x4adb20`.
- All entries are initially populated with the address of a default trap handler (`0x401d10`), which halts execution and reports invalid opcodes.
- Specific opcode slots are populated with dedicated VM execution routines:

| Opcode ID | Handler Address | Instruction Class | Functional Role |
| :--- | :--- | :--- | :--- |
| `0x17` (23) | `0x401be0` | ALU | Add top two stack elements |
| `0x1a` (26) | `0x401c40` | ALU | Subtract |
| `0x26` (38) | `0x401c90` | ALU | Bitwise XOR |
| `0x35` (53) | `0x401c00` | ALU | Bitwise AND |
| `0x4d` (77) | `0x401c20` | Shift | Bitwise Left Shift / Rotate |
| `0x5d` (93) | `0x401bb0` | Comparison | Compare equality (`==`) |
| `0x60` (96) | `0x401d20` | Memory | Load flag character at index |
| `0x68` (104) | `0x401c70` | Stack | Push 32-bit immediate constant |
| `0x99` (153) | `0x401b20` | Stack | Duplicate top of stack (`DUP`) |
| `0xa9` (169) | `0x401cb0` | Flow | Conditional jump if non-zero |
| `0xcd` (205) | `0x401b00` | Flow | Unconditional jump |
| `0xcf` (207) | `0x401b50` | State | Push VM status register |
| `0xea` (234) | `0x401b80` | Flow | Subroutine call / return |
| `0xef` (239) | `0x401ce0` | VM Control | Halt / Verify success condition |
| `0xfe` (254) | `0x401da0` | System | Check stack pointer boundary |

### 2. Bytecode Decryption Engine (`0x401d60`)
The VM executes bytecode located in the `.rodata` segment starting at address `0x482140` (length: 4,010 bytes, spanning up to offset `0xfaa`).
Unlike standard interpreters that read plain bytecode, `ghostvm` dynamically decrypts each 5-byte instruction tuple `(opcode: 1 byte, operand: 4 bytes)` at runtime using a cascading XOR stream cipher:
```c
uint8_t byte = (index * 7) & 0xff;
byte ^= r13_key[index & 0x0f];   // 16-byte key table at 0x483200
byte ^= r12_cipher[index];       // Ciphertext table at 0x482140
```
This dynamic decryption prevents trivial linear static disassembly without first applying the decryption algorithm.

### 3. Execution Loop & Verification
The execution engine maintains a 64-slot operand stack on the thread execution frame.
1. `fgets` reads user input into buffer `rbx` at `0x4ae340`.
2. Length validation verifies the input format.
3. The VM interpreter loops through 802 instructions.
4. Intermediate input characters undergo multi-round cryptographic mixing (XOR masks, rotations, and parity checks).
5. At opcode `0xef`, the evaluation flag `[rsp + 0x13c]` is checked. If it equals `1`, `main` prints `"Access granted."`.

---

## Reproduction & Verification
To execute the binary locally:
```bash
chmod +x /home/tracehanami/Downloads/CTFs/CREST/GhostVM/ghostvm
/home/tracehanami/Downloads/CTFs/CREST/GhostVM/ghostvm
```
Entering an invalid candidate triggers:
```text
ghost> test
Nope.
```

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Binary | `ghostvm` | 64-bit ELF binary containing custom virtual machine |
