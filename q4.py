import dpkt
import socket

pcap = 'telescope_cs575_2025S1.pcap'

d = set()
with open(pcap, 'rb') as f:
    r = dpkt.pcap.Reader(f)
    for ts, buf in r:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == 0x0800:
            continue
        ip = eth.data
        d.add(socket.inet_ntoa(ip.dst))

if not d:
    print("No IP addresses found"); exit()

def ip2i(x):
    a, b, c, d = map(int, x.split('.'))
    return a << 24 | b << 16 | c << 8 | d

def i2ip(i):
    return '.'.join(str((i>>s)&255) for s in [24, 16, 8, 0])

vals = sorted(ip2i(x) for x in d)
lo, hi = vals[0], vals[-1]

p = 0
for k in range(31, -1, -1):
    if (lo >> k) & 1 == (hi >> k) & 1:
        p += 1
    else:
        break

mask = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
base = lo & mask
size = 1 << (32 - p)

print(f"Estmated telescope prefix: {i2ip(base)}/{p}")
print(f"Estimated telescope size: {size}")