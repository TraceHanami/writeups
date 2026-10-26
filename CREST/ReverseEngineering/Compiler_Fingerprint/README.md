# CREST CTF 2026 — REV-6: Compiler Fingerprint (Ghost Mantis)

**Category:** Reverse Engineering  
**CTF Event:** CREST CTF 2026  
**Artifacts:**
- `files_yxxA7E9.zip` (7,254 bytes)
- `player/mantis_alpha` (14,400 bytes ELF 64-bit binary)
- `player/mantis_beta` (14,392 bytes ELF 64-bit binary)
- `player/mantis_gamma` (14,400 bytes ELF 64-bit binary)
- `player/README.md`
- `solve.py` (7,476 bytes) & `solve(1).py` (7,910 bytes)  
**Status:** Solved  
**Candidate Flag:** `CREST{clang_23_O2_fp_ssp_pie}`  

---

## 1. Challenge Overview

During an incident response investigation, three malware tools attributed to the "Ghost Mantis" threat group were recovered: `mantis_alpha`, `mantis_beta`, and `mantis_gamma`. The objective is to analyze the binary compilation artifacts, identify the unique toolchain/compiler version, optimization level, and build traits that link these executables together, and formulate the flag:
```
CREST{compiler_version_buildtraits}
```

---

## 2. Binary & Static Trait Analysis

Running static binary inspection via `solve.py` over all three ELF binaries extracts shared compiler and hardening flags:
- **ELF Type:** Position-Independent Executable (PIE enabled)
- **RELRO:** Partial RELRO
- **Stack Protection:** Stack canaries present (`__stack_chk_fail`)
- **Frame Pointers:** Frame pointer omission disabled (`-fno-omit-frame-pointer`, explicit `push rbp; mov rbp, rsp`)
- **Control-flow Enforcement Technology (CET):** CET IBT/SHSTK disabled (`crt_endbr: False`)
- **Fortify Source:** Disabled (`fortify: False`)
- **GLIBC Version Floor:** GLIBC 2.34
- **Shared Function Prologue Marker:** Instruction sequence `xor eax, eax; add eax, 0; nop` present across all three binaries.

---

## 3. Codegen Differential Matching

The solver script `solve.py` compares the assembly instructions of function bodies across candidate compilers (`clang-16` through `clang-23`, `gcc-11` through `gcc-14`):
- Clang 23 with `-O2 -fno-omit-frame-pointer -fstack-protector -fPIE` produces a **97.31% average instruction similarity** with the Ghost Mantis binaries:
  - `mantis_beta`: 1.000 (Exact match modulo relocations)
  - `mantis_gamma`: 1.000 (Exact match modulo relocations)
  - `mantis_alpha`: 0.9192 match

Deriving the canonical token format according to challenge specifications yields the flag:
```text
CREST{clang_23_O2_fp_ssp_pie}
```
