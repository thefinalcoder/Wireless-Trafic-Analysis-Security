import dpkt

pcap = 'telescope_cs575_2025S1.pcap'

count = 0
with open(pcap, 'rb') as f:
    r = dpkt.pcap.Reader(f)
    for ts, buf in r:
        count += 1

print(f"Total packets: {count}") 