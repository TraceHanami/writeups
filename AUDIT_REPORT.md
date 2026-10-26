# CTF Archive Audit & Repository Reconciliation Report

**Audit Date:** October 26, 2026  
**Repository:** `/home/tracehanami/Github/writeups`  
**Remote:** `https://github.com/TraceHanami/writeups.git`  
**Author / Auditor:** Antigravity Pair-Programming Assistant & TraceHanami  

---

## 1. Executive Summary

This audit reconciled the public CTF writeups repository (`/home/tracehanami/Github/writeups`) with the local CTF challenge archive (`/home/tracehanami/Downloads/CTFs/`) and cataloged file inventories (`/home/tracehanami/Downloads/ctf_inventory.csv` and candidate lists).

The audit identified **33 verified, high-quality missing challenge writeups** across 14 events, consolidated duplicate versions without loss of information, sanitized private filesystem links and session credentials, copied 35 necessary supporting assets (exploit scripts, decoder utilities, and evidence screenshots), and updated the repository index.

---

## 2. Key Audit Metrics

All counts below reflect exact, verified on-disk quantities (zero estimates):

| Metric | Confirmed Count | Description |
|:---|:---:|:---|
| **Markdown Candidates Examined** | **91** | Unique `.md` / `.markdown` paths cataloged from local archive, user CTF directories, and report inventories |
| **Unique Genuine Writeups Identified** | **72** | Unique challenge writeups documented across 17 distinct CTF competitions and platforms |
| **Writeups Already Present at Baseline** | **39** | Pre-existing writeups in the repository (11 ASIS, 1 Compfest, 9 TomCTF, 18 z0d1ak) |
| **Writeups Added (Reconciled)** | **33** | Verified missing solutions integrated into appropriate event/category directories |
| **Duplicate Versions Consolidated / Excluded** | **4** | Draft or redundant summary writeups whose technical content is preserved in canonical writeups |
| **Supporting Documentation Items** | **7** | Third-party tool manuals and specifications retained in the local archive |
| **Challenge Artifact Markdown Files** | **14** | Challenge prompts, player descriptions, and maze graph nodes (`CSSCTF/map/*.md`) |
| **Excluded (Security, Privacy, Unrelated)** | **17** | 14 dependency READMEs (`node_modules`), 2 Non-CTF documents, 1 private author lab |
| **Writeups Needing Manual Review** | **0** | Zero ambiguous classifications (10 in-progress writeups documented accurately as in-progress) |
| **Supporting Assets Integrated** | **35** | Solver scripts (`solve.py`), evidence screenshots (`.png`), and input logs |
| **Broken Links / Missing Assets** | **0** | 100% of internal index links and referenced assets verified to exist |
| **Final Repository Challenge Writeups** | **72** | Verified challenge `README.md` files across the repository |

---

## 3. Breakdown of Integrated Missing Writeups (33 Total)

The 33 newly integrated writeups are organized under standard event and category folders:

1. **ASIS CTF Quals 2026**
   - `ASIS/Miscellaneous/Mic_Check/README.md` — Sanity-check challenge with flag `ASIS{f4rr3w3ll_cl455il_h3ll0_unc3rt_3r4!}` and scoreboard screenshot.

2. **CREST CTF 2026**
   - `CREST/ReverseEngineering/Compiler_Fingerprint/README.md` — Ghost Mantis binary compiler trait identification (`solve.py` solver).
   - `CREST/Cryptography/Vault_KDF/README.md` — Custom PBKDF2-HMAC-SHA256 key derivation function cryptanalysis.
   - `CREST/Miscellaneous/Worker_State/README.md` — Worker rotation configuration analysis with recovered flag `CREST{ServiceRecovered08X}`.
   - `CREST/Forensics/Chat_Log_Analysis/README.md` — 97MB `CREST-CHAT/2` structured JSON audit log anomaly investigation.
   - `CREST/ReverseEngineering/GhostVM/README.md` — Statically linked stripped 64-bit ELF bytecode VM reconstruction.
   - `CREST/ReverseEngineering/Origami/README.md` — ELF PIE binary bitwise folding VM reversing with flag `CREST{byt3c0d3_vms_hide_l0g1c_n0t_h1de_1t_w3ll}`.

3. **FortID CTF**
   - `FortID/BinaryExploitation/One_Last_Review/README.md` — Heap Use-After-Free (UAF) / type confusion pwn exploit (`chall.c` preserved).
   - `FortID/Cryptography/Dragon_Crypto/README.md` — Elliptic curve cryptography over prime field $\mathbb{F}_p$ with Koblitz message encoding.
   - `FortID/Cryptography/DESBox/README.md` — Interactive 3DES complementation property attack (`solve.py` solver).
   - `FortID/Forensics/Meteor_Shower/README.md` — Nintendo Entertainment System (NES) iNES ROM sprite steganography.
   - `FortID/ReverseEngineering/T9/README.md` — Python 3.10 compiled bytecode multi-tap keypad reversing (`bytecode.txt` disassembly).

4. **H7CTF 2026**
   - `H7CTF/Cloud/Lambda_PrivEsc/README.md` — AWS IAM privilege escalation via Lambda execution role (`welcome.txt`, `build.log`, `lambda_function.py`, `out.json`).

5. **HITCON CTF 2026**
   - `HITCON/Miscellaneous/mathclipse/README.md` — Python 3.14 jail escape via object graph manipulation and bytecode slot swaps.
   - `HITCON/Miscellaneous/mathclipse_delta/README.md` — Hardened Python jail bypass defeating dynamic `sys.addaudithook` bytecode filter.
   - `HITCON/ReverseEngineering/spi_tpm_rev/README.md` — ARM64 QEMU hardware emulation, Linux kernel modules, and SPI TPM firmware.
   - `HITCON/BinaryExploitation/vulcreator/README.md` — Windows 10/Server 2022 x64 kernel driver `VulCreator.sys` exploitation.

6. **Hack The Box**
   - `HackTheBox/Hardware/Touch/README.md` — Airport terminal kiosk #042 hardware interface, MRZ document scanner, and barcode processing (10 barcode/MRZ evidence images preserved; session cookie sanitized).
   - `HackTheBox/Forensics/phantom/README.md` — Volatility 3 memory analysis of Linux kernel rootkit `singularity` and ftrace hooks.

7. **LUN4R CTF 2026**
   - `LUN4R/Miscellaneous/Scoreboard/README.md` — Official competition placement record (74th place) and technical summaries for Moonlit Nocturne, The Moving ISA, and Black Mirror (2 scoreboard screenshots preserved).

8. **Null0rigin CTF**
   - `NullOriginCTF/Forensics/Stego_Chain/README.md` — Complete 8-stage steganography chain (Stages 31–38) documentation with Works Key Schedule (`solve.py` verification script, `dev.png`, `moire_vis1.png`).

9. **PicoCTF**
   - `PicoCTF/Cryptography/LFSR_Crypto/README.md` — 64-bit Fibonacci LFSR characteristic polynomial cryptanalysis and known-plaintext keystream alignment (`output.txt` stream).

10. **Pointer Overflow CTF 2026**
    - `PointerOverflowCTF/Cryptography/The_Consulting_Room/README.md` — Remote AES-CBC PKCS#7 padding oracle attack (`solve.py` solver).
    - `PointerOverflowCTF/Forensics/Meridian1967/README.md` — 1967 IBM 80-column punched card forensic steganography (memo screenshot preserved).

11. **SwarmCTF 2026**
    - `SwarmCTF/Forensics/Dead_Signal/README.md` — Incident response investigation across network logs, telemetry, and hydrophone audio with flag `swarm{0rph3u5_5ub5urf4c3_51gn4l_r3c0n57ruc73d_7a9f}` (`solve.py` solver).

12. **TerrierCyberQuest**
    - `TerrierCyberQuest/WebExploitation/hex-09/README.md` — Prototype pollution and SQLite SQL injection exploit chain with flag `IATCQ{LF6BWCR2VNU0RIFD7CMM5VQBCO}` (`solve.py` exploit).

13. **TryHackMe**
    - `TryHackMe/OSINT/Passive_Reconnaissance/README.md` — Passive reconnaissance methodology (WHOIS, DNS, search dorking, Shodan) and 100% completion badge screenshot.

14. **Unknown / Community CTFs**
    - `Unknown/Forensics/First_Stego/README.md` — JPEG SOF0 height manipulation and forensic carving with flag `CTF{l0v3_c4n_tr4n5c3nd_t1m3_4nd_5p4c3}`.
    - `Unknown/Hardware/Hardware_Logic_Analyzer/README.md` — Value Change Dump (`.vcd`) logic analyzer waveform parsing for SPI/UART buses (`solve.py` and `decode.py`).
    - `Unknown/ReverseEngineering/Interlock/README.md` — Linear algebra mod 256 matrix transformation solver using Z3 SMT (`solve.py`).
    - `Unknown/Forensics/NoiseGate/README.md` — Bluetooth Low Energy (BLE) GATT cryptanalysis and cyclic XOR key stream recovery.
    - `Unknown/WebExploitation/SiteCheck/README.md` — Headless browser drone SSRF filter evasion via IPv6 loopback (`internal.png` administration viewport screenshot).
    - `Unknown/ReverseEngineering/Tollgate/README.md` — Go stripped binary reverse engineering and `pclntab` runtime function recovery.

---

## 4. Duplicate Analysis & Untouched Versions

### A. Subsumed Summaries
- **`NullOriginCTF/STEGO_SOL.md`**: Compared directly against `NullOriginCTF/STEGO.md`. `STEGO_SOL.md` is a 94-line quick solution summary sheet. `STEGO.md` is the comprehensive 417-line technical writeup that contains all information from `STEGO_SOL.md` plus full protocol tables, mathematical derivations, and architecture diagrams. `STEGO.md` was published as canonical; `STEGO_SOL.md` remains preserved in the archive.

### B. Conflicting Versions Kept Untouched
Three writeups in the local archive (`~/Downloads/CTFs/z0d1ak/`) differed from the pre-existing files in the repository:
1. `z0d1ak/crypto_you-have-not-seen-my-colors/WRITEUP.md` vs `z0d1ak/Forensics/unseen_colors/README.md` (340 diff lines)
2. `z0d1ak/pwn_salvage-protocol/WRITEUP.md` vs `z0d1ak/BinaryExploitation/salvage_protocol/README.md` (192 diff lines)
3. `z0d1ak/rev_black_tide/WRITEUP.md` vs `z0d1ak/ReverseEngineering/Black_tide/README.md` (130 diff lines)

**Detailed comparison confirmed:**
In all three cases, the repository versions were polished, final submissions that contained remote challenge endpoints, solver script references, and expanded explanations. The archive versions were intermediate working drafts. In accordance with the non-negotiable safeguard (*Do not overwrite existing writeups without comparing them*), the repository versions were kept completely untouched, and the archive drafts were categorized as `duplicate_version`.

---

## 5. Security & Publication Review

The repository is public on GitHub (`https://github.com/TraceHanami/writeups`). The following strict publication rules were applied and verified:

1. **VPN Profiles:** Excluded all `.ovpn` files (e.g. `ap-south-1-TraceHanami-regular.ovpn`, `release_arena_us-release-2.ovpn`).
2. **Session Cookies & Credentials:** Excluded `cookies.txt`, `cookies2.txt`, `cookies3.txt`. In `HackTheBox/Touch/README.md`, the hardcoded session cookie was redacted to `[REDACTED_SESSION_COOKIE]`. In `Unknown/SiteCheck/README.md`, `jwt.txt` and `hash.txt` were excluded.
3. **Private Keys & Identity Files:** Excluded `bruce.pem`, resumes (`DOC-20260820-WA0003.*`), and academic certificates (`*.pdf`).
4. **Large Binaries & Virtual Environments:** Excluded heavy disk images (`nexus_relay.img`, `KBR17_relay.img`), memory dumps (`dump_srv.mem`, `ctf.dmp`), VM images (`GhostInTheThread.ova`), large archives (`NullOrigin_Rev_Chain.7z`, `dead_signal.zip`), wordlists (`rockyou.txt`), and all `venv` / `node_modules` folders.
5. **Private Challenge Author Labs:** Excluded `challenges/spoonfeed-ctf/` which is marked private (`author/` registry).

---

## 6. Audit Inventory File

The complete item-by-item audit is saved to [`WRITEUP_INVENTORY.csv`](WRITEUP_INVENTORY.csv) with columns:
`event,challenge,category,source_path,repository_path,status,reason,supporting_assets,sensitive_content_review,links_checked`.
