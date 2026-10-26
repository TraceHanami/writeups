# HackTheBox - Phantom Forensic Writeup

## Challenge Overview
* **Category:** Forensics / Memory Forensics
* **Target OS:** Ubuntu Linux (`6.8.0-87-generic`)
* **Artifacts Provided:**
  * `dump_srv.mem` (Memory capture taken using AVML)
  * `Ubuntu_6.8.0-87-generic.json` (Volatility 3 Linux symbol table)

---

## Executive Summary
A Linux workstation was compromised by an advanced kernel rootkit named **`singularity`**. The rootkit was loaded as an unsigned, out-of-tree kernel module and immediately unlinked from the kernel's module list to avoid detection by standard tools like `lsmod`. It established extensive `ftrace` and `tracepoint` hooks (83 hooks in total) to hide files, processes, and network connections, while providing covert channels and privilege escalation mechanisms. Multiple persistent reverse shells connected to a Command & Control (C2) server were identified.

---

## Key Questions & Findings

| # | Question / Investigation Item | Finding / Answer |
|---|---|---|
| 1 | **Hidden kernel module name** | `singularity` |
| 2 | **Kernel taint flags set by module** | `OOT_MODULE, UNSIGNED_MODULE` |
| 3 | **Exact load time (seconds since boot)** | `2490.473832` |
| 4 | **PID of process that loaded the module** | `2669` |
| 5 | **Kernel tracepoint hooked by rootkit** | `sched_process_fork` |
| 6 | **C2 server IP address** | `192.168.200.164` |
| 7 | **C2 server listening port** | `8081` |
| 8 | **Compromised bash process PIDs (ascending)** | `2693, 2695, 2698` |
| 9 | **Total number of installed hooks** | `83` (82 ftrace + 1 tracepoint) |
| 10 | **Function hooked to hide IPv4 connections** | `tcp4_seq_show` |
| 11 | **Number of hooked `getdents` variants** | `5` |
| 12 | **Function hooked for ICMP covert channel** | `icmp_rcv` |
| 13 | **Centralized callback function address** | `0xffffc0b3aac0` |
| 14 | **Suspicious environment variable for privilege escalation** | `OPERATOR=access` (Value: `access`) |

---

## Detailed Forensic Walkthrough

### 1. Rootkit Identification & Loading Details
Using Volatility 3's `linux.malware.hidden_modules` plugin:
```bash
vol -s . -f dump_srv.mem linux.malware.hidden_modules.Hidden_modules
```
**Result:**
* **Module Name:** `singularity`
* **Address / Offset:** `0xffffc0b42640`
* **Code Size:** `0x19000`
* **Taint Flags:** `OOT_MODULE, UNSIGNED_MODULE`

Inspecting the kernel ring buffer logs with `linux.kmsg.Kmsg`:
```bash
vol -s . -f dump_srv.mem linux.kmsg.Kmsg
```
**Key Logs:**
```text
kern  warn    2490.473832  Task(2669)  singularity: loading out-of-tree module taints kernel.
kern  notice  2490.473840  Task(2669)  singularity: module verification failed: signature and/or required key missing - tainting kernel
```
* **Load Time:** `2490.473832` seconds since boot
* **Loader PID:** `2669`

---

### 2. Kernel Hooking Mechanism & Analysis

#### A. Kernel Tracepoint Hooking
Analyzing tracepoints using `linux.tracing.tracepoints.CheckTracepoints`:
```bash
vol -s . -f dump_srv.mem linux.tracing.tracepoints.CheckTracepoints
```
* **Hooked Tracepoint:** `sched_process_fork`
* **Probe Address:** `0xffffc0b3a990`
* **Module:** `singularity`

#### B. Ftrace Hooking Analysis
Checking `ftrace` hooks using `linux.tracing.ftrace.CheckFtrace`:
```bash
vol -s . -f dump_srv.mem linux.tracing.ftrace.CheckFtrace
```
* **Total ftrace hooks:** 82 functions hooked.
* **Centralized Handler / Callback:** `0xffffc0b3aac0`
* **Key Intercepted Functions:**
  * **Hiding IPv4 Connections:** `tcp4_seq_show` (filters `/proc/net/tcp` output).
  * **Hiding IPv6 Connections:** `tcp6_seq_show`
  * **Covert ICMP Channel:** `icmp_rcv` (intercepts ICMP packets directly in kernel space).
  * **Hiding Files/Directories:** Intercepts 5 variations of directory entry queries:
    1. `__x64_sys_getdents64`
    2. `__x64_sys_getdents`
    3. `__ia32_sys_getdents64`
    4. `__ia32_sys_getdents`
    5. `__ia32_compat_sys_getdents`
  * **System Calls & Execution:** `__x64_sys_openat`, `__x64_sys_read`, `__x64_sys_write`, `__x64_sys_kill`, `__x64_sys_bpf`, etc.

---

### 3. Network & C2 Infrastructure

Examining socket structures using `linux.sockstat.Sockstat`:
```bash
vol -s . -f dump_srv.mem linux.sockstat.Sockstat
```

**Identified C2 Connections:**
```text
Process: bash (PID: 2693) -> 192.168.200.177:48440 <--> 192.168.200.164:8081 (ESTABLISHED)
Process: bash (PID: 2695) -> 192.168.200.177:48444 <--> 192.168.200.164:8081 (ESTABLISHED)
Process: bash (PID: 2698) -> 192.168.200.177:48454 <--> 192.168.200.164:8081 (ESTABLISHED)
```
* **C2 IP:** `192.168.200.164`
* **C2 Port:** `8081`
* **Compromised PIDs:** `2693, 2695, 2698` (Standard reverse shell handles redirected to FDs 0, 1, 2).

---

### 4. Privilege Escalation & Attacker Activity

#### A. Environment Variables (`linux.envars.Envars`)
```text
PID: 2792 | Process: bash | Variable: OPERATOR | Value: access
```

#### B. Command History (`linux.bash.Bash`)
```text
2774  bash  2025-11-19 17:40:57 UTC  clear
2774  bash  2025-11-19 17:41:02 UTC  OPERATOR=access bash
2792  bash  2025-11-19 17:41:06 UTC  kill -59 $$
2792  bash  2025-11-19 17:41:08 UTC  internal_fifos
2792  bash  2025-11-19 17:41:08 UTC  ps aufwx
2861  bash  2025-11-19 17:41:24 UTC  clear
2861  bash  2025-11-19 17:41:29 UTC  ./avml dump_srv.mem
```

**Analysis:**
1. The user/attacker spawned a new bash instance with `OPERATOR=access bash`.
2. By executing `kill -59 $$` (or triggering specific hooked syscalls), the rootkit checks for the presence of the magic environment variable `OPERATOR=access` and grants root credentials (`uid=0, gid=0`) to the calling process.
3. The analyst subsequently dumped the memory using `./avml dump_srv.mem`.
