import pyshark
from collections import Counter

# Load the PCAP file
pcap_file = "2022-MTA-workshop-exercise-5-of-5.pcap"
cap = pyshark.FileCapture(pcap_file, display_filter="ip")

# Extract IPs and protocols
src_ips, dst_ips, protocols = [], [], []

for packet in cap:
    try:
        if "IP" in packet:
            src_ips.append(packet.ip.src)
            dst_ips.append(packet.ip.dst)
        if hasattr(packet, "highest_layer"):
            protocols.append(packet.highest_layer)
    except AttributeError:
        continue

# Count occurrences
ip_counts = Counter(src_ips + dst_ips)
protocol_counts = Counter(protocols)

# Print Results
print("\n[+] Top Source & Destination IPs:")
for ip, count in ip_counts.most_common(10):
    print(f"{ip}: {count} occurrences")

print("\n[+] Protocols Used:")
for proto, count in protocol_counts.most_common():
    print(f"{proto}: {count} packets")

cap.close()

