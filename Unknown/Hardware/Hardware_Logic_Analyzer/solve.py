# decode_spi.py
clk='$'
mosi='%'
miso='&'
cs="'"

t=0
vals={clk:'0',mosi:'0',miso:'0',cs:'1'}

mosi_bits=[]
miso_bits=[]

with open("capture.vcd") as f:
    for line in f:
        line=line.strip()
        if not line:
            continue

        if line.startswith('#'):
            t=int(line[1:])
            continue

        if len(line)>=2 and line[0] in "01":
            vals[line[1]]=line[0]

            # sample on SPI rising edge while CS asserted
            if line[1]==clk and line[0]=='1' and vals[cs]=='0':
                mosi_bits.append(vals[mosi])
                miso_bits.append(vals[miso])

def bits_to_bytes(bits):
    out=[]
    for i in range(0,len(bits)-7,8):
        b=''.join(bits[i:i+8])
        out.append(int(b,2))
    return out

mb=bits_to_bytes(mosi_bits)
ib=bits_to_bytes(miso_bits)

print("MOSI bytes:")
print(' '.join(f'{x:02x}' for x in mb))
print("ASCII:")
print(''.join(chr(x) if 32<=x<127 else '.' for x in mb))

print()
print("MISO bytes:")
print(' '.join(f'{x:02x}' for x in ib))
print("ASCII:")
print(''.join(chr(x) if 32<=x<127 else '.' for x in ib))
