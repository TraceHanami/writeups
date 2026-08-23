# misc/genie - Writeup

## Challenge Overview
- **Category:** Reverse Engineering / Game Boy / Misc
- **Handout:** `seal.gb` (Game Boy ROM), `PORT.md`
- **Flag:** `zdk{thre3_WordS_nINE_3ChoE5_oNe_oPeN_5e41}`

The challenge presents a custom Game Boy DMG cartridge (`seal.gb`) and a remote verification service. The service generates a 16-bit session seed, patches it into the cartridge, and evaluates an automated input "movie" (Joypad inputs and memory cheat injections) containing at most 12 cheat codes within 3,600 frames.

---

## 1. Static Analysis & Reverse Engineering

### ROM & Architecture
- **Platform:** Nintendo Game Boy (SM83 CPU).
- **RAM Layout & State Variables:**
  - `0xC100`: Player Gold Word ($w_0$).
  - `0xC102`: Checksum Word 1 ($w_1$).
  - `0xC104`: Checksum Word 2 ($w_2$).
  - `0xC406`: Current Floor ($1, 2, 3, 9$).
  - `0xC408 - 0xC409`: Decoded 16-bit Session Seed ($s$).
  - `0xC40A`: Readiness flag ($R$).
  - `0xC40B`: Joypad previous frame register.
  - `0xC40C`: Frame tick counter.
  - `0xC410`, `0xC411`: Player coordinate $(X, Y)$, spawned at $(2, 3)$.
  - `0xC412`: Floor 9 Echo counter ($E$).
  - `0xC200`, `0xC202`: Seal state register and accumulator.
  - `0xC300`: Floor 9 opcode dispatch / cheat register.

---

### Cartridge Seed Transformation (`0x04A5`)
At startup (`0x0E81`), the raw seed provided in the cartridge header at `0xC0F0` is decoded via routine `0x04A5` before being saved to `0xC408`:

$$\text{internal\_seed} = \left(\text{rol}((\text{raw\_seed} \oplus \text{0xA5C3}), 7) + \text{0x3D29}\right) \oplus \text{0x6B71}$$

In Python:
```python
def rol(val, n, bits=16):
    return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)

def func_04a5(de):
    de_xor = de ^ 0xa5c3
    bc = rol(de_xor, 7)
    hl = (0x3d29 + bc) & 0xffff
    c = (hl & 0xff) ^ 0x71
    b = ((hl >> 8) & 0xff) ^ 0x6b
    return (b << 8) | c
```

---

### Gold Integrity Verification (`0x0A37`)
Every game tick, subroutine `0x0A37` verifies that the player's gold $w_0$ has not been illegally modified without valid checksum codewords $w_1$ and $w_2$:
1. $w_1 = w_0 \oplus s$
2. $w_2 = h(w_0, s)$, where $h(w, s)$ is a non-linear mixer at `0x0578`:

```python
def h_step(w, s):
    de = w ^ s
    bc = rol(de, 3)
    hl = (0x6d2b + bc) & 0xffff
    de_s = rol(s, 7)
    de_xor = hl ^ de_s
    return rol(de_xor, 5)

def get_codewords(gold_val, seed):
    w0 = gold_val & 0xffff
    w1 = (w0 ^ seed) & 0xffff
    w2 = h_step(w0, seed)
    return w0, w1, w2
```

If these codewords mismatch, the game reverts all gold to stored fallback values.

---

## 2. Floor Breakdown & Strategy

### Floors 1 & 2
- **Spawn Position:** $(2, 3)$
- **Objectives:**
  - Chest at $(5, 6)$ (+48 gold).
  - Monster at $(13, 9)$ (+24 gold).
  - Gate at $(17, 15)$ (costs 50 gold).
- **Movement:** Input requires rising edge button transitions (`0 -> 1 -> 0`).
- **Pathing:**
  - $(2, 3) \xrightarrow{3\times\text{Right}} (5, 3) \xrightarrow{3\times\text{Down}} (5, 6)$ [Chest]
  - $(5, 6) \xrightarrow{8\times\text{Right}} (13, 6) \xrightarrow{3\times\text{Down}} (13, 9)$ [Monster]
  - $(13, 9) \xrightarrow{4\times\text{Right}} (17, 9) \xrightarrow{6\times\text{Down}} (17, 15)$ [Gate]
  - Press `START` to spend 50 gold and advance floor.

### Floor 3 (5,000 Gold Gate)
Floor 3 requires 5,000 gold. Instead of farming, we use 3 cheat codes to inject:
- `[0xC100] = 5000` ($w_0$)
- `[0xC102] = 5000 ^ internal_seed` ($w_1$)
- `[0xC104] = h(5000, internal_seed)` ($w_2$)

Then walk directly to the gate at $(17, 15)$ ($15\times\text{Right}$, $12\times\text{Down}$) and press `START` to reach Floor 9.

---

### Floor 9 (Vault Authenticator Sequence)
On Floor 9, the game checks the accumulator state against target vault word `0xB14A` located in ROM at `0x020F`.

1. **State Equation Inversion:**
   Accumulator is updated by $g(x) = \text{rol}(x \oplus \text{0xBEEF}, 3) + \text{0x4A3D}$.
   Inverting $g(x) = \text{0xB14A}$ gives required state $x = \text{0x120E}$.
2. **Path Finding:**
   Starting state at floor 9 init is `0x1D0F`.
   BFS over the permutation operations $f(x, k)$ for $k \in \{0, 1, 2\}$ yields the unique 9-step sequence:
   $$\mathbf{[2, 0, 2, 1, 2, 2, 0, 2, 1]}$$
3. **Cheat Injection Synchronization:**
   When `A` is pressed on frame $F$, the game sets $R = 1$ and resets `0xC300` to `0xFE`. On frame $F+1$, the handler reads `[0xC300]`. Therefore, injecting `[0xC300] = k` on frame $F+1$ executes the $k$-th echo transformation, clearing all 9 echoes and unlocking the seal.

Total cheat codes used: **12 / 12** (3 for Floor 3 gold + 9 for Floor 9 echoes).

---

## 3. Exploit Script

```python
import socket
import ssl
import json
import re

def rol(val, n, bits=16):
    return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)

def h_step(w, s):
    de = w ^ s
    bc = rol(de, 3)
    hl = (0x6d2b + bc) & 0xffff
    de_s = rol(s, 7)
    de_xor = hl ^ de_s
    return rol(de_xor, 5)

def func_04a5(de):
    de_xor = de ^ 0xa5c3
    bc = rol(de_xor, 7)
    hl = (0x3d29 + bc) & 0xffff
    c = (hl & 0xff) ^ 0x71
    b = ((hl >> 8) & 0xff) ^ 0x6b
    return (b << 8) | c

def get_codewords(gold_val, seed):
    w0 = gold_val & 0xffff
    w1 = (w0 ^ seed) & 0xffff
    w2 = h_step(w0, seed)
    return w0, w1, w2

def generate_winning_movie(server_seed):
    internal_seed = func_04a5(server_seed)
    
    RIGHT, LEFT, UP, DOWN = 1, 2, 4, 8
    A, START = 16, 128

    joypad = []

    def press(btn):
        joypad.append(btn)
        joypad.append(0)

    def idle(count=1):
        for _ in range(count):
            joypad.append(0)

    # 1. Boot settlement
    idle(80)

    # 2. Floor 1 (Clear Chest, Monster, Gate)
    for _ in range(3): press(RIGHT)
    for _ in range(3): press(DOWN)
    for _ in range(8): press(RIGHT)
    for _ in range(3): press(DOWN)
    for _ in range(4): press(RIGHT)
    for _ in range(6): press(DOWN)
    idle(5)
    press(START)
    idle(30)

    # 3. Floor 2 (Clear Chest, Monster, Gate)
    for _ in range(3): press(RIGHT)
    for _ in range(3): press(DOWN)
    for _ in range(8): press(RIGHT)
    for _ in range(3): press(DOWN)
    for _ in range(4): press(RIGHT)
    for _ in range(6): press(DOWN)
    idle(5)
    press(START)
    idle(30)

    # 4. Floor 3 (Inject 5,000 gold codewords)
    f3_cheat_frame = len(joypad)
    w0, w1, w2 = get_codewords(5000, internal_seed)
    codes = [
        [f3_cheat_frame, 0xc100, w0],
        [f3_cheat_frame, 0xc102, w1],
        [f3_cheat_frame, 0xc104, w2]
    ]

    for _ in range(15): press(RIGHT)
    for _ in range(12): press(DOWN)
    idle(5)
    press(START)
    idle(40)

    # 5. Floor 9 (Echo Sequence)
    sequence = [2, 0, 2, 1, 2, 2, 0, 2, 1]
    for k in sequence:
        idle(5)
        f_press = len(joypad)
        press(A)
        codes.append([f_press + 1, 0xc300, k])

    idle(120)

    return {
        "version": 1,
        "seed": server_seed,
        "joypad": joypad,
        "codes": codes
    }

def solve(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            buf = b""
            while b"movie-json>" not in buf:
                buf += ssock.recv(1024)
            
            seed = int(re.search(r"seed=(\d+)", buf.decode()).group(1))
            print(f"[+] Server seed: {seed}")
            
            movie = generate_winning_movie(seed)
            payload = json.dumps(movie) + "\n"
            ssock.sendall(payload.encode())
            
            resp = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                print(chunk.decode(errors="ignore"), end="", flush=True)

if __name__ == "__main__":
    solve("genie-cff1e74d34b8.chals.z0d1ak.org", 1337)
```
