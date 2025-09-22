import dpkt
import collections

pcap = 'telescope_cs575_2025S1.pcap'

protocols = collections.Counter()
ipv4 = 0


with open(pcap, 'rb') as f:
    r = dpkt.pcap.Reader(f)
    for ts, buf in r:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != 0x0800:
            continue
        ip = eth.data
        ipv4 += 1
        protocols[ip.p] += 1

proto_names = {1:"ICMP", 6:"TCP", 17:"UDP", 2:"IGMP", 47:"GRE", 50:"ESP", 51:"AH"}

print("Top 5 IPv4 protocols (by packet share):")
print("{:<8} {:>12} {:>10}".format("Proto","Count","Percent"))
for proto, cnt in proto_counter.most_common(5):
    name = proto_names.get(proto, f"PROTO-{proto}")
    pct = (cnt / ipv4_total) * 100
    print("{:<8} {:>12} {:>9.2f}%".format(name, cnt, pct))

print("Total IPv4 packets:", ipv4_total)