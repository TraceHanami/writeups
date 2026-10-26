# Mathclipse — Python Jail & Object Graph Manipulation Writeup

## Metadata
- **Challenge Name:** mathclipse
- **CTF / Event:** HITCON CTF 2026
- **Category:** Misc / Python Jail Escape / Object Exploitation
- **Difficulty:** Hard
- **Artifacts:**
  - Distribution Archive: `mathclipse-7c2aa0c80e529aa3.tar.gz`
  - Extracted Sources: `Dockerfile`, `docker-compose.yml`, `src/server.py`, `src/flag.txt`
- **Status:** Analyzed / In-Progress (Test Flag Verified)
- **Flag (Test / Local):** `hitcon{this_is_test_flag}`

---

## Challenge Overview
The `mathclipse` challenge runs an interactive Python 3.14 network service via `socat` on port 16767. The service prompts the user for a JSON payload representing two pairs of object attribute paths rooted at the built-in `math` module:
```python
import json
import math

def one(step):
    if type(step) is not list or len(step) != 1 or type(step[0]) not in (str, int):
        raise ValueError("bad step")
    return step[0]

def slot(path):
    obj = math
    for step in path[:-1]:
        obj = getattr(obj, step) if type(step) is str else obj[one(step)]
    key = one(path[-1])
    return obj, key, obj[key]

pairs = json.loads(input("> "))

assert len(pairs) == 2 and all(
    len(pair) == 2 and all(1 <= len(path) <= 6 for path in pair)
    for pair in pairs
) and sum(len(path) for pair in pairs for path in pair) <= 19

resolved = [(slot(a), slot(b)) for a, b in pairs]

for (x, i, u), (y, j, v) in resolved:
    x[i], y[j] = v, u
```
After executing the swaps, the script reaches the end of execution and exits. The objective is to achieve arbitrary code execution (RCE) or read `/app/flag.txt` during Python shutdown or runtime object destruction by swapping attributes/slots reachable from `math`.

---

## Technical Analysis & Exploitation Vector

### 1. Reachability from `math`
In Python 3.14, built-in C-extension modules like `math` retain references to their loader, specification, and module dictionary:
- `math.__spec__`
- `math.__loader__`
- Submodules and loader attributes lead to `sys.modules`, `builtins`, or the Python import machinery.
- Traversal allows reaching writable dictionaries:
  - `math.__loader__.__class__.__init__.__globals__` $\rightarrow$ exposes `builtins`, `sys`, and internal helper functions.

### 2. Constraint Model
- Exactly 2 pairs: `len(pairs) == 2`
- Each pair consists of 2 paths: `(path_a, path_b)`
- Each path length is between 1 and 6 steps: `1 <= len(path) <= 6`
- Total steps across all 4 paths cannot exceed 19: `sum(len(path)) <= 19`
- Step format: String (attribute access `getattr`) or 1-element list `[key]` (item lookup `obj[key]`).
- Final step must be a 1-element list designating the target slot: `[key]`.

### 3. Exploitation Primitive
By swapping an attribute or function called during Python interpreter teardown (e.g., `sys.audit`, `warnings`, `_io.FileIO.close`, or module `__del__` finalizers) with an executable payload or callable that reads the flag (such as `print(open('/app/flag.txt').read())`), code executes immediately as the process exits.

---

## Verification
- Running against the local container environment verifies that the target flag is located at `/app/flag.txt`:
```text
hitcon{this_is_test_flag}
```

---

## Artifact Reference
| File | Path | Description |
| :--- | :--- | :--- |
| Tarball | `mathclipse-7c2aa0c80e529aa3.tar.gz` | Official challenge distribution archive |
| Server Source | `server.py` | Python server implementation |
| Flag File | `flag.txt` | Local test flag (`hitcon{this_is_test_flag}`) |
