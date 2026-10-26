# SPI TPM Rev — Hardware Emulation & Kernel Exploit Writeup

## Metadata
- **Challenge Name:** spi-tpm-rev
- **CTF / Event:** HITCON CTF 2026
- **Category:** Pwn / Hardware Reverse Engineering / Kernel Exploitation
- **Difficulty:** Hard
- **Artifacts:**
  - Distribution Archive: `spi-tpm-rev-e15a21887cc92581.tar.gz`
  - Emulation Infrastructure:
    - Custom QEMU Binary: `src/qemu-system-aarch64`
    - Linux AArch64 Kernel: `src/Image`
    - Firmware Shared Library: `src/libspi_tpm_firmware.so`
    - Kernel Modules: `src/modules/spi_tpm_client.ko`, `src/modules/spi_tpm_dma.ko`
    - Root Filesystem: `src/initramfs.cpio.gz`
    - Service Launch Scripts: `run.sh`, `connection.sh`, `Dockerfile`, `docker-compose.yml`
- **Status:** Analyzed / In-Progress
- **Flag (Distribution / Local):** `hitcon{REDACTED-2}`

---

## Challenge Architecture
The challenge instantiates an isolated ARM64 virtual machine using a custom patched build of QEMU (`qemu-system-aarch64`):
```bash
qemu-system-aarch64 \
    -machine virt,gic-version=3 \
    -cpu cortex-a57 \
    -device spi-tpm-dma,id=spi0_dma \
    -device spi-tpm-sram,id=spi0_sram,size=8192 \
    -device stm32h7-spi,id=spi0,dma-backend=spi0_dma,sram-backend=spi0_sram,fifo-size=32 \
    -device "spi-tpm,bus=ssi,firmware-path=$root/libspi_tpm_firmware.so" \
    -kernel "$root/Image" \
    -initrd "$runtime_initramfs"
```
The VM injects `/flag` with mode `0400` owned by root. An unprivileged user shell is provided over standard I/O. Players must exploit vulnerabilities in the custom hardware emulation layer or the Linux kernel driver `spi_tpm_client.ko` to achieve kernel execution and read the flag.

---

## Reverse Engineering & Vulnerability Vectors

### 1. Hardware Emulation Layer (`libspi_tpm_firmware.so`)
The simulated SPI TPM device interfaces via an SSI bus and emulates a Trusted Platform Module with custom firmware loaded from `libspi_tpm_firmware.so`.
- Inspecting `libspi_tpm_firmware.so` reveals custom command handlers for TPM initialization, state attestation, and DMA transfers.
- Boundary checks during bulk DMA read/write commands between `spi0_dma` and `spi0_sram` can be leveraged to corrupt QEMU memory structures or achieve guest-to-host execution if QEMU escape is required.

### 2. Linux Kernel Driver (`spi_tpm_client.ko`)
Inside the guest, `spi_tpm_client.ko` creates a character device exposing `ioctl()` primitives for user-space programs to communicate with the virtual TPM:
- Static analysis of `spi_tpm_client.ko` identifies memory mapping and user-controlled buffer copy operations (`copy_from_user` / `copy_to_user`).
- Integer overflow or out-of-bounds indexing in the transfer descriptor parsing logic permits arbitrary kernel write, enabling privilege escalation to root (`commit_creds(prepare_kernel_cred(0))`).

---

## Proof-of-Work & Connection
Remote instances enforce an `scrypt` proof-of-work wrapper configured in `connection.sh`:
- Salt: `spi-tpm-pow-v1:<prefix>`
- Cost parameters: $N=32768, r=8, p=1$
- Target: 8 leading zero bits.

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Tarball | `spi-tpm-rev-e15a21887cc92581.tar.gz` | Complete distribution archive |
| Kernel Module | `src/modules/spi_tpm_client.ko` | Target Linux kernel driver |
| TPM Firmware | `src/libspi_tpm_firmware.so` | Shared library implementing emulated TPM hardware logic |
| Flag | `flag` | Distribution flag placeholder (`hitcon{REDACTED-2}`) |
