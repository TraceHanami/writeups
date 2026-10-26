# decode_uart.py
tx='!'

events=[]
t=0
state='1'

with open("capture.vcd") as f:
    for line in f:
        line=line.strip()
        if not line:
            continue

        if line.startswith('#'):
            t=int(line[1:])
            continue

        if len(line)>=2 and line[1]==tx:
            state=line[0]
            events.append((t,state))

# estimate bit period from first few transitions
d=[]
for i in range(1,min(100,len(events))):
    d.append(events[i][0]-events[i-1][0])

print("min transition:",min(d))
print("max transition:",max(d))
