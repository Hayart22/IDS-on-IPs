from scapy.all import sniff
from scapy.layers.inet import IP, TCP, ICMP

# Dictionary to store packet count per source IP
packet_count = {}

# Threshold for number of packets from same source
THRESHOLD = 20


def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src

      
        if src_ip not in packet_count:
            packet_count[src_ip] = 1
        else:
            packet_count[src_ip] += 1

      
        if TCP in packet and packet[TCP].flags == 'S':
            print(f"⚠️ SYN Packet detected from {src_ip}  Untitled1:23 - ids_app.py:23")

        
        if ICMP in packet:
            print(f"⚠️ ICMP Packet detected from {src_ip}  Untitled1:27 - ids_app.py:27")

       
        if packet_count[src_ip] > THRESHOLD:
            print(f"🚨 Potential attack from {src_ip}, packet count: {packet_count[src_ip]}  Untitled1:31 - ids_app.py:31")

# Start sniffing
print("🟢 IDS is running... Press Ctrl+C to stop  Untitled1:34 - ids_app.py:34")
sniff(prn=analyze_packet, store=0)  # store=0 to save memory


