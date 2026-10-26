# 📓 CTF Writeups — TraceHanami

A curated collection of **72 Capture The Flag (CTF) challenge writeups** at the intermediate to advanced level — documenting solutions, exploit methodologies, and key learnings across core cybersecurity domains.

---

## 🗂️ Categories

| Category | Description | Writeup Count |
|:---|:---|:---:|
| 🌐 Web Exploitation | SQL Injection, prototype pollution, SSRF, authentication bypass | 4 |
| 🔐 Cryptography | Classical ciphers, LFSR, AES padding oracle, ECC, KDF, 3DES | 19 |
| 🔍 Forensics & Steganography | Memory forensics, BLE packets, audio signal analysis, stego chains | 20 |
| 💻 Reverse Engineering | VM bytecode reversing, compiler traits, Go pclntab, kernel modules | 16 |
| 🐚 Pwn / Binary Exploitation | Heap UAF, type confusion, custom VM escapes, Windows driver pwn | 5 |
| ☁️ Cloud & Infrastructure | AWS IAM privilege escalation, Lambda execution roles | 1 |
| 🔌 Hardware Security | Logic analyzer VCD waveforms, SPI/UART decoding, kiosk interfaces | 2 |
| 🕵️ OSINT | Open-source intelligence, DNS/WHOIS recon, search engine dorking | 1 |
| 🔢 Miscellaneous | Python jail escapes, logic puzzles, blockchain, competition records | 12 |

---

## 📐 Writeup Structure

Each writeup follows a consistent format:

```
<event>/
└── <category>/
    └── <challenge-name>/
        ├── README.md       ← Writeup (approach, steps, solution, flags)
        └── solve.py        ← Exploit or solve script (where applicable)
```

Every challenge `README.md` covers:

- **Challenge description** and source (platform, event)
- **Difficulty** and point value
- **Tools used**
- **Step-by-step approach** with reasoning and mathematical proofs
- **Key vulnerability or concept** explained
- **Flag** (verified and documented)

> 💡 **Challenge Artifact Note:** In accordance with repository curation standards, large challenge binaries, raw memory dumps (`.mem`, `.dmp`), virtual machine images (`.ova`), and full disk captures (`.img`) are stored separately in the local archive. This repository hosts curated writeups, mathematical derivations, reproducible solver scripts, and essential evidence captures.

---

## 🛠️ Common Tools

`Python 3` · `Burp Suite` · `CyberChef` · `Ghidra` · `GDB / pwndbg` · `Wireshark` · `Volatility 3` · `Z3 SMT Solver` · `binwalk` · `stegsolve` · `Audacity`

---

## 📚 Challenge Index (72 Challenges)

### ASIS CTF Quals (12)
- [ASIS_Arch](ASIS/ReverseEngineering/ASIS_Arch/README.md) — `Reverse Engineering`
- [Fence](ASIS/Cryptography/Fence/README.md) — `Cryptography`
- [Hackel](ASIS/Cryptography/Hackel/README.md) — `Cryptography`
- [Headache](ASIS/Cryptography/Headache/README.md) — `Cryptography`
- [LeakMeAk](ASIS/ReverseEngineering/LeakMeAk/README.md) — `Reverse Engineering`
- [Less_is_more](ASIS/Cryptography/Less_is_more/README.md) — `Cryptography`
- [Linchan](ASIS/Cryptography/Linchan/README.md) — `Cryptography`
- [Mario](ASIS/Cryptography/Mario/README.md) — `Cryptography`
- [Mic_Check](ASIS/Miscellaneous/Mic_Check/README.md) — `Miscellaneous`
- [Pancake](ASIS/Cryptography/Pancake/README.md) — `Cryptography`
- [Revenant_Buddy](ASIS/BinaryExploitation/Revenant_Buddy/README.md) — `Binary Exploitation`
- [Sultan](ASIS/Cryptography/Sultan/README.md) — `Cryptography`

### Compfest (1)
- [BurhanGuild-Loader-Incident](Compfest/Forensics/BurhanGuild-Loader-Incident/README.md) — `Forensics`

### CREST CTF 2026 (6)
- [Chat_Log_Analysis](CREST/Forensics/Chat_Log_Analysis/README.md) — `Forensics`
- [Compiler_Fingerprint](CREST/ReverseEngineering/Compiler_Fingerprint/README.md) — `Reverse Engineering`
- [GhostVM](CREST/ReverseEngineering/GhostVM/README.md) — `Reverse Engineering`
- [Origami](CREST/ReverseEngineering/Origami/README.md) — `Reverse Engineering`
- [Vault_KDF](CREST/Cryptography/Vault_KDF/README.md) — `Cryptography`
- [Worker_State](CREST/Miscellaneous/Worker_State/README.md) — `Miscellaneous`

### FortID CTF (5)
- [DESBox](FortID/Cryptography/DESBox/README.md) — `Cryptography`
- [Dragon_Crypto](FortID/Cryptography/Dragon_Crypto/README.md) — `Cryptography`
- [Meteor_Shower](FortID/Forensics/Meteor_Shower/README.md) — `Forensics`
- [One_Last_Review](FortID/BinaryExploitation/One_Last_Review/README.md) — `Binary Exploitation`
- [T9](FortID/ReverseEngineering/T9/README.md) — `Reverse Engineering`

### H7CTF 2026 (1)
- [Lambda_PrivEsc](H7CTF/Cloud/Lambda_PrivEsc/README.md) — `Cloud`

### Hack The Box (2)
- [phantom](HackTheBox/Forensics/phantom/README.md) — `Forensics`
- [Touch](HackTheBox/Hardware/Touch/README.md) — `Hardware`

### HITCON CTF 2026 (4)
- [mathclipse](HITCON/Miscellaneous/mathclipse/README.md) — `Miscellaneous`
- [mathclipse_delta](HITCON/Miscellaneous/mathclipse_delta/README.md) — `Miscellaneous`
- [spi_tpm_rev](HITCON/ReverseEngineering/spi_tpm_rev/README.md) — `Reverse Engineering`
- [vulcreator](HITCON/BinaryExploitation/vulcreator/README.md) — `Binary Exploitation`

### LUN4R CTF 2026 (1)
- [Scoreboard](LUN4R/Miscellaneous/Scoreboard/README.md) — `Miscellaneous`

### Null0rigin CTF (1)
- [Stego_Chain](NullOriginCTF/Forensics/Stego_Chain/README.md) — `Forensics`

### PicoCTF (1)
- [LFSR_Crypto](PicoCTF/Cryptography/LFSR_Crypto/README.md) — `Cryptography`

### Pointer Overflow CTF 2026 (2)
- [Meridian1967](PointerOverflowCTF/Forensics/Meridian1967/README.md) — `Forensics`
- [The_Consulting_Room](PointerOverflowCTF/Cryptography/The_Consulting_Room/README.md) — `Cryptography`

### SwarmCTF 2026 (1)
- [Dead_Signal](SwarmCTF/Forensics/Dead_Signal/README.md) — `Forensics`

### TerrierCyberQuest (1)
- [hex-09](TerrierCyberQuest/WebExploitation/hex-09/README.md) — `Web Exploitation`

### TomCTF (9)
- [Broken Timeline](TomCTF/Cryptography/Broken Timeline/README.md) — `Cryptography`
- [Shinobi RNG](TomCTF/Cryptography/Shinobi RNG/README.md) — `Cryptography`
- [Dimensional Expansion](TomCTF/Forensics/Dimensional Expansion/README.md) — `Forensics`
- [Fate in Colors](TomCTF/Forensics/Fate in Colors/README.md) — `Forensics`
- [Story of Captain Levi](TomCTF/Forensics/Story of Captain Levi/README.md) — `Forensics`
- [Sun God’s Whisper](TomCTF/Forensics/Sun God’s Whisper/README.md) — `Forensics`
- [Cursed Transmission](TomCTF/Miscellaneous/Cursed Transmission/README.md) — `Miscellaneous`
- [Ghost in the VGA](TomCTF/Miscellaneous/Ghost in the VGA/README.md) — `Miscellaneous`
- [Petals of Promise](TomCTF/Miscellaneous/Petals of Promise/README.md) — `Miscellaneous`

### TryHackMe (1)
- [Passive_Reconnaissance](TryHackMe/OSINT/Passive_Reconnaissance/README.md) — `OSINT`

### Unknown / Community CTFs (6)
- [First_Stego](Unknown/Forensics/First_Stego/README.md) — `Forensics`
- [Hardware_Logic_Analyzer](Unknown/Hardware/Hardware_Logic_Analyzer/README.md) — `Hardware`
- [Interlock](Unknown/ReverseEngineering/Interlock/README.md) — `Reverse Engineering`
- [NoiseGate](Unknown/Forensics/NoiseGate/README.md) — `Forensics`
- [SiteCheck](Unknown/WebExploitation/SiteCheck/README.md) — `Web Exploitation`
- [Tollgate](Unknown/ReverseEngineering/Tollgate/README.md) — `Reverse Engineering`

### z0d1ak CTF (18)
- [house_xiii](z0d1ak/BinaryExploitation/house_xiii/README.md) — `Binary Exploitation`
- [salvage_protocol](z0d1ak/BinaryExploitation/salvage_protocol/README.md) — `Binary Exploitation`
- [Cyclotomic](z0d1ak/Cryptography/Cyclotomic/README.md) — `Cryptography`
- [Rewind](z0d1ak/Cryptography/Rewind/README.md) — `Cryptography`
- [Rewind_Revenge](z0d1ak/Cryptography/Rewind_Revenge/README.md) — `Cryptography`
- [siren](z0d1ak/Cryptography/siren/README.md) — `Cryptography`
- [Dead_current](z0d1ak/Forensics/Dead_current/README.md) — `Forensics`
- [dead_letter](z0d1ak/Forensics/dead_letter/README.md) — `Forensics`
- [ghost_in_the_cpu](z0d1ak/Forensics/ghost_in_the_cpu/README.md) — `Forensics`
- [unrotated](z0d1ak/Forensics/unrotated/README.md) — `Forensics`
- [unseen_colors](z0d1ak/Forensics/unseen_colors/README.md) — `Forensics`
- [BlockChain](z0d1ak/Miscellaneous/BlockChain/README.md) — `Miscellaneous`
- [Ihate_DAA](z0d1ak/Miscellaneous/Ihate_DAA/README.md) — `Miscellaneous`
- [Black_tide](z0d1ak/ReverseEngineering/Black_tide/README.md) — `Reverse Engineering`
- [GENIE](z0d1ak/ReverseEngineering/GENIE/README.md) — `Reverse Engineering`
- [HUSK](z0d1ak/ReverseEngineering/HUSK/README.md) — `Reverse Engineering`
- [star_blow](z0d1ak/ReverseEngineering/star_blow/README.md) — `Reverse Engineering`
- [Hydra](z0d1ak/WEB/Hydra/README.md) — `Web Exploitation`

---

## 🎯 Purpose

These writeups serve as:

- A **personal knowledge base** for revisiting techniques
- A **learning resource** for intermediate to advanced CTF players
- A **reference** for understanding real-world vulnerability classes and exploit chains

> ⚠️ All challenges documented here are from legal CTF competitions and practice platforms. Content is shared strictly for educational purposes.

---

## 👤 Author

**TraceHanami** — Intermediate to advanced CTF player and cybersecurity researcher.

---

## 📄 License

Content in this repository is for educational use only.
