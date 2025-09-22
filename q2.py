import dpkt

pcap = 'telescope_cs575_2025S1.pcap'

first = None
last = None
bits = 0

with open(pcap, 'rb') as f:
    r = dpkt.pcap.Reader(f)
    for ts, buf in r:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != 0x0800:
            continue
        ip = eth.data
        bits += ip.len * 8
        if first is None:
            first = ts
        last = ts

duration = last - first
avg_bits = bits / duration
print(f"Average IP traffic: {avg_bits} bits/second")