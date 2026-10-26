# Hardware Logic Analyzer — SPI & UART Signal Forensics

**Category:** Hardware Security / Signal Analysis  
**CTF Event:** Unknown CTF (Consolidated under Unknown)  
**Artifacts:**
- `capture.vcd` (44,596 bytes Value Change Dump waveform)
- `capture.txt` (44,596 bytes duplicate waveform log)
- `decode.py` (558 bytes UART transition parser)
- `solve.py` (1,100 bytes SPI synchronous decoder)
- `spi_region.txt` (10,321 bytes isolated SPI packet traces)  
**Status:** In-Progress / Signal Reconstruction  

---

## 1. Challenge Overview

The challenge provides a logic analyzer recording in Value Change Dump (`.vcd`) format, capturing hardware bus interactions between a microcontroller and external peripherals (an asynchronous serial console and an SPI flash memory / sensor).

---

## 2. Signal Mapping & Protocol Identification

Inspecting the header and transition syntax of `capture.vcd`:
- `'!'` $\rightarrow$ UART Serial TX line (asynchronous 1-wire serial)
- `'$'` $\rightarrow$ SPI Clock line (SCK)
- `'%'` $\rightarrow$ Master Out Slave In (MOSI)
- `'&'` $\rightarrow$ Master In Slave Out (MISO)
- `'\''` $\rightarrow$ Chip Select line (CS# / active low)

### A. UART Analysis (`decode.py`)
`decode.py` parses timestamps `#<time>` and identifies state transitions on line `'!'`.
Calculating delta times between successive edges:
```python
d = []
for i in range(1, min(100, len(events))):
    d.append(events[i][0] - events[i-1][0])
```
The minimum transition duration reveals the base baud rate (115200 baud standard framing: 1 start bit, 8 data bits, 1 stop bit).

### B. SPI Bus Extraction (`solve.py`)
`solve.py` tracks active chip-select state `vals[cs] == '0'` and samples MOSI and MISO lines strictly on the rising edge of the clock signal (`clk == '$' and state == '1'`):
```python
# sample on SPI rising edge while CS asserted
if line[1] == clk and line[0] == '1' and vals[cs] == '0':
    mosi_bits.append(vals[mosi])
    miso_bits.append(vals[miso])
```

Grouping sampled bits into 8-bit octets converts the binary stream into byte sequences for both master transmission (`MOSI`) and slave response (`MISO`). The extracted bytes contain command sequences (e.g. read status, read memory `0x03`) and subsequent memory readout payloads.
