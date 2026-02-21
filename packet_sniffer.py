import scapy.all as scapy
import argparse

# Function to mask IP addresses
def mask_ip(ip):
    return '.'.join(ip.split('.')[:3]) + '.0'

# Function to decode packets
def decode_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        print(f"IP: {mask_ip(ip_layer.src)} -> {mask_ip(ip_layer.dst)}")
    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        print(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}")
    if packet.haslayer(scapy.UDP):
        udp_layer = packet[scapy.UDP]
        print(f"UDP: {udp_layer.sport} -> {udp_layer.dport}")
    if packet.haslayer(scapy.DNS):
        dns_layer = packet[scapy.DNS]
        print(f"DNS: {dns_layer.qd.qname}")
    if packet.haslayer(scapy.Raw):
        http_payload = packet[scapy.Raw].load
        if b'HTTP' in http_payload:
            print(f"HTTP Payload: {http_payload[:50]}")

# Main function to read pcap files
def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('pcap_file', help='Path to the pcap file')
    args = parser.parse_args()

    # Load pcap file
    packets = scapy.rdpcap(args.pcap_file)
    
    for packet in packets:
        decode_packet(packet)

if __name__ == '__main__':
    main()
