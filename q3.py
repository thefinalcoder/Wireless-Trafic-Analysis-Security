import dpkt

pcap = 'telescope_cs575_2025S1.pcap'

ipv4 = 0
total = 0

with open(pcap, 'rb') as f:
    r = dpkt.pcap.Reader(f)
    for ts, buf in r:
        total += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == 0x0800:
            ipv4 += 1

print(f"Total packets: {total}")
print(f"IPv4 packets: {ipv4}")