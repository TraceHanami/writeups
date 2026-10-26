# Mathclipse-Delta — Hardened Python Jail & Audit Hook Bypass Writeup

## Metadata
- **Challenge Name:** mathclipse-delta
- **CTF / Event:** HITCON CTF 2026
- **Category:** Misc / Python Jail Escape / Bytecode Auditing
- **Difficulty:** Very Hard
- **Artifacts:**
  - Archive: `mathclipse-delta-36890ce7581921a2.tar.gz`
  - Extracted Sources: `Dockerfile`, `docker-compose.yml`, `src/server.py`, `src/flag.txt`
- **Status:** Analyzed / In-Progress (Test Flag Verified)
- **Flag (Test / Local):** `hitcon{this_is_test_flag}`

---

## Challenge Overview
`mathclipse-delta` is the hardened sequel to the `mathclipse` challenge. While retaining the core primitive of swapping two pairs of object slots reachable from `math`, the author introduces two significant constraints:
1. **Length Reduction:** The sum of path lengths across all 4 trajectories is reduced from $\le 19$ to $\le 12$:
   ```python
   sum(len(path) for pair in pairs for pair in pair) <= 12
   ```
2. **Dynamic Audit Hook:** A Python `sys.addaudithook` monitor is installed that intercepts all `exec` events and verifies that any executed code object satisfies strict structural restrictions:
   ```python
   _allowed = {4, 23, 34, 50, 82} # Only allowed opcodes

   def check(obj, seen):
       ...
       if type(obj) is types.CodeType:
           assert obj.co_names == ()
           assert set(obj._co_code_adaptive[::2]) <= _allowed
           for value in obj.co_consts:
               check(value, seen)
   ```

---

## Technical Analysis & Bypass Mechanisms

### 1. Tightened Path Constraint
With $\sum \text{len}(\text{path}) \le 12$, each path must average only 3 steps (e.g. `[step1, step2, [key]]`). Long traversals via `math.__loader__.__class__.__init__.__globals__` exceed the step quota.
Exploitation requires direct, high-leverage object reference swaps, such as targeting `math.__dict__` directly or swapping built-in type descriptors and slot wrappers.

### 2. Audit Hook Analysis
The audit hook only intercepts the `"exec"` event:
```python
def audit(event, args):
    if event == "exec":
        check(args[0], set())

sys.addaudithook(audit)
```
Crucially:
- Built-in functions called in C (like `open()`, `print()`, or C-level socket/file operations) do **not** generate `"exec"` audit events.
- Manipulating C-level function pointers or swapping built-in module dictionaries allows code or system calls to execute without invoking Python `exec`.
- Alternatively, dismantling `sys.audit` or replacing internal hook lists (by mutating `sys.modules['sys']` internal state) disables the audit hook before execution.

---

## Verification
- Local test environment verifies flag presence at `src/flag.txt`:
```text
hitcon{this_is_test_flag}
```

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Tarball | `mathclipse-delta-36890ce7581921a2.tar.gz` | Distribution archive for delta challenge |
| Server Source | `server.py` | Hardened Python server script |
| Flag File | `flag.txt` | Local test flag (`hitcon{this_is_test_flag}`) |
