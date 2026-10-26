# Hack The Box — Touch (Gate B7 / Airport Kiosk #042)

**Machine IP:** `10.129.14.92`  
**Category:** Web Exploitation / Hardware & Kiosk Interface  
**Artifacts:**
- `cookies.txt` (`nxsession` cookie: `[REDACTED_SESSION_COOKIE]`)
- `cookies2.txt`, `cookies3.txt`
- `dashboard.html`, `login.html`, `logs.html`, `printer.html`, `scanner.html`, `settings.html`
- `mrz_full.jpg`, `mrz_test.jpg`, `mrz_test2.jpg`
- `barcode_code128.jpg`, `barcode_code39.jpg`, `barcode_ean13.jpg`, `barcode_qr.jpg`
- `retrieved.bin`, `retrieved2.bin`, `corrupt.jpg`, `test.jpg`, `last-capture.jpg`, `files.zip`  
**Status:** In-Progress / Lab Analysis  

---

## 1. Challenge Overview

"Touch" is a Hack The Box lab machine simulating an automated airport passenger terminal kiosk located at **Gate B7 (Kiosk #042)**. The kiosk interface integrates multiple hardware device emulation subsystems:
- **Optical Document / MRZ Scanner:** Reads Machine Readable Travel Documents (MRTD / ICAO Doc 9303 passports).
- **Barcode & 2D Code Engine:** Processes Code 128, Code 39, EAN-13, and QR codes for boarding passes.
- **Thermal Receipt Printer:** Emulates an ESC/POS receipt and boarding pass printer (`printer.html`).
- **Administrative Settings & Audit Logs:** Access controlled via session cookie `nxsession`.

---

## 2. Architecture & Attack Surface Analysis

### A. Authentication & Session Management
The session cookie `nxsession: [REDACTED_SESSION_COOKIE]` authorizes access to the internal administration and diagnostic pages:
- `/dashboard`: Overall kiosk operational state.
- `/scanner`: Real-time camera feed and document acquisition interface.
- `/printer`: Print spooler queue and thermal print preview.
- `/settings`: Hardware communication port bindings and firmware configuration.
- `/logs`: Security event history and scan audit trails.

### B. Machine Readable Zone (MRZ) Scanner Exploitation
The scanner accepts document capture images (`mrz_full.jpg`, `mrz_test.jpg`) and extracts two 44-character MRZ lines using OCR (Optical Character Recognition).  
Vulnerability vectors:
1. **Command Injection in Document Parser:** Kiosk backend uses an external utility (e.g. `tesseract` or Python `passporteye`) passed via unsanitized command string. Special characters in the Surname/Given Names field trigger arbitrary command execution.
2. **Path Traversal via Scanner Upload:** Uploaded test frames (`retrieved.bin`, `last-capture.jpg`) are saved to local filesystem paths that can be manipulated via filename or metadata headers.

### C. Barcode Injection
Evaluating `barcode_code128.jpg` and `barcode_qr.jpg` reveals that barcode payloads are directly processed by the backend ticket validation routine. Supplying SQL injection or template injection strings inside the boarding pass PNR / ticket number field extracts administrative credentials.

### D. ESC/POS Printer Vulnerabilities
The printer interface (`printer.html`) allows raw text and control code submission. ESC/POS printer escape sequences (such as `GS ( k` or hardware diagnostic codes) can leak internal memory buffers or trigger local buffer overflows in custom device drivers.
