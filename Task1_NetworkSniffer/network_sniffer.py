"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')

    print(f"\n{'─'*50}")
    print(f"  📦 Packet #{packet_count}  [{timestamp}]")
    print(f"{'─'*50}")

    if IP in packet:
        ip = packet[IP]
        print(f"  🌐 Source IP      : {ip.src}")
        print(f"  🌐 Destination IP : {ip.dst}")
        print(f"  🌐 TTL            : {ip.ttl}")

        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.sprintf('%TCP.flags%')
            print(f"  🔗 Protocol       : TCP")
            print(f"  🔗 Source Port    : {tcp.sport}")
            print(f"  🔗 Dest Port      : {tcp.dport}")
            print(f"  🔗 Flags          : {flags}")

        elif UDP in packet:
            udp = packet[UDP]
            print(f"  📡 Protocol       : UDP")
            print(f"  📡 Source Port    : {udp.sport}")
            print(f"  📡 Dest Port      : {udp.dport}")

        elif ICMP in packet:
            print(f"  📨 Protocol       : ICMP")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"  📄 Payload        : {payload[:50]}")

print("="*50)
print("  🔍 CodeAlpha - Network Sniffer Started")
print("  Capturing 20 packets... (Ctrl+C to stop)")
print("="*50)

sniff(prn=packet_callback, count=20, store=False)

print(f"\n✅ Done! Captured {packet_count} packets.")
