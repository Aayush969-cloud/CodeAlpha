"""
from scapy.all import sniff

# Function to display packet details
def packet_callback(packet):
    try:
        # Display IP addresses and protocol type if the packet has IP layer
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            protocol = packet["IP"].proto
            print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        else:
            print("Non-IP packet detected")  # For packets without IP layer
    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniff packets, print details of 10 packets (adjust count for more)
print("Starting network sniffer...")
sniff(prn=packet_callback, count=10)  # Count set to 10; set to 0 for continuous capture
"""




from scapy.all import sniff, IP

def packet_handler(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {source_ip} -> Destination IP: {destination_ip} | Protocol: {protocol}")

print("Starting network sniffer...")
# Capture only 10 packets, for example
sniff(prn=packet_handler, count=10)
