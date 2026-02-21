#!/usr/bin/env python3
"""
Ethical Packet Sniffer - CTEC 450 Project
Reads packets from pcap files and decodes IP, TCP, UDP, DNS, and HTTP protocols.
Implements privacy-preserving features: IP masking, email redaction, and sensitive data handling.
Safe for educational lab use only.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, rdpcap
from scapy.layers.http import HTTP, HTTPRequest


class PacketSniffer:
    """Ethical packet sniffer with privacy-preserving features."""

    # Regex patterns for sensitive data detection
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    PHONE_PATTERN = re.compile(r'\b(?:\+1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b')

    def __init__(self, pcap_file: str, verbose: bool = False, redact: bool = True):
        """
        Initialize the packet sniffer.

        Args:
            pcap_file: Path to the pcap file to read
            verbose: Enable verbose output
            redact: Enable sensitive data redaction
        """
        self.pcap_file = Path(pcap_file)
        self.verbose = verbose
        self.redact = redact
        self.packet_count = 0
        self.statistics = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'dns_packets': 0,
            'http_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
        }

    def mask_ip_address(self, ip: str) -> str:
        """
        Mask IP addresses for privacy.
        Format: XXX.XXX.XXX.xxx (only last octet shown)

        Args:
            ip: IP address string

        Returns:
            Masked IP address
        """
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        except Exception:
            pass
        return "XXX.XXX.XXX.xxx"

    def redact_sensitive_data(self, data: str) -> str:
        """
        Redact sensitive information from strings.

        Args:
            data: String potentially containing sensitive data

        Returns:
            String with sensitive data redacted
        """
        if not self.redact or not data:
            return data

        # Redact emails
        data = self.EMAIL_PATTERN.sub('[REDACTED_EMAIL]', data)

        # Redact credit card numbers
        data = self.CREDIT_CARD_PATTERN.sub('[REDACTED_CARD]', data)

        # Redact social security numbers
        data = self.SSN_PATTERN.sub('[REDACTED_SSN]', data)

        # Redact phone numbers
        data = self.PHONE_PATTERN.sub('[REDACTED_PHONE]', data)

        return data

    def safe_bytes_decode(self, data: bytes, max_length: int = 200) -> str:
        """
        Safely decode bytes to string, handling encoding errors gracefully.

        Args:
            data: Bytes to decode
            max_length: Maximum length of output string

        Returns:
            Safely decoded string
        """
        try:
            decoded = data[:max_length].decode('utf-8', errors='ignore')
            return self.redact_sensitive_data(decoded)
        except Exception:
            return '[UNDECODABLE_DATA]'

    def parse_ip_packet(self, packet) -> Dict:
        """Parse IP layer information."""
        ip_info = {
            'src_ip': self.mask_ip_address(packet[IP].src) if self.redact else packet[IP].src,
            'dst_ip': self.mask_ip_address(packet[IP].dst) if self.redact else packet[IP].dst,
            'ttl': packet[IP].ttl,
            'protocol': packet[IP].proto,
            'packet_length': len(packet),
        }
        self.statistics['ip_packets'] += 1
        return ip_info

    def parse_tcp_packet(self, packet) -> Dict:
        """Parse TCP layer information."""
        tcp_info = {
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'flags': packet[TCP].flags,
            'seq': packet[TCP].seq,
            'ack': packet[TCP].ack,
        }
        self.statistics['tcp_packets'] += 1
        return tcp_info

    def parse_udp_packet(self, packet) -> Dict:
        """Parse UDP layer information."""
        udp_info = {
            'src_port': packet[UDP].sport,
            'dst_port': packet[UDP].dport,
            'length': packet[UDP].len,
        }
        self.statistics['udp_packets'] += 1
        return udp_info

    def parse_dns_packet(self, packet) -> Dict:
        """Parse DNS layer information."""
        dns_info = {
            'is_response': packet[DNS].qr,
            'queries': [],
            'answers': [],
        }

        # Parse DNS queries
        if DNSQR in packet:
            qr = packet[DNSQR]
            dns_info['queries'].append({
                'name': qr.qname.decode('utf-8', errors='ignore').rstrip('.'),
                'type': qr.qtype,
            })

        # Parse DNS answers
        if DNSRR in packet:
            rr = packet[DNSRR]
            dns_info['answers'].append({
                'name': rr.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                'type': rr.type,
                'rdata': str(rr.rdata),
            })

        self.statistics['dns_packets'] += 1
        return dns_info

    def parse_http_packet(self, packet) -> Dict:
        """Parse HTTP layer information."""
        http_info = {
            'method': 'UNKNOWN',
            'host': 'UNKNOWN',
            'path': 'UNKNOWN',
            'user_agent': 'UNKNOWN',
        }

        try:
            if HTTPRequest in packet:
                http_req = packet[HTTPRequest]
                http_info['method'] = http_req.Method.decode('utf-8', errors='ignore')
                http_info['host'] = http_req.Host.decode('utf-8', errors='ignore')
                http_info['path'] = http_req.Path.decode('utf-8', errors='ignore')
                if 'User-Agent' in http_req.fields:
                    http_info['user_agent'] = http_req['User-Agent'].decode('utf-8', errors='ignore')
        except Exception as e:
            if self.verbose:
                print(f"    [HTTP parsing note: {str(e)[:50]}]")

        self.statistics['http_packets'] += 1
        return http_info

    def parse_payload(self, packet) -> Optional[str]:
        """Extract and safely decode packet payload."""
        if Raw in packet:
            payload = packet[Raw].load
            return self.safe_bytes_decode(payload, max_length=200)
        return None

    def process_packet(self, packet) -> None:
        """Process and display packet information."""

        Args:
            packet: Scapy packet object
        """
        self.packet_count += 1
        self.statistics['total_packets'] += 1

        print(f"\n{'='*80}")
        print(f"Packet #{{self.packet_count}}")
        print(f"{'='*80}")

        # Parse IP layer
        if IP in packet:
            ip_info = self.parse_ip_packet(packet)
            print(f"[IP] {{ip_info['src_ip']}} -> {{ip_info['dst_ip']}}")
            print(f"     TTL: {{ip_info['ttl']}}, Length: {{ip_info['packet_length']}} bytes")

            # Parse TCP
            if TCP in packet:
                tcp_info = self.parse_tcp_packet(packet)
                print(f"[TCP] Port {{tcp_info['src_port']}} -> {{tcp_info['dst_port']}}")
                print(f"      Flags: {{tcp_info['flags']}}, Seq: {{tcp_info['seq']}}, Ack: {{tcp_info['ack']}}")

                # Check for HTTP
                if 80 in (tcp_info['src_port'], tcp_info['dst_port']):
                    if Raw in packet:
                        http_info = self.parse_http_packet(packet)
                        print(f"[HTTP] {{http_info['method']}} to {{http_info['host']}}{{http_info['path']}}")

            # Parse UDP
            elif UDP in packet:
                udp_info = self.parse_udp_packet(packet)
                print(f"[UDP] Port {{udp_info['src_port']}} -> {{udp_info['dst_port']}}")

                # Check for DNS
                if DNS in packet:
                    dns_info = self.parse_dns_packet(packet)
                    if dns_info['queries']:
                        for query in dns_info['queries']:
                            print(f"[DNS] Query: {{query['name']}}")
                    if dns_info['answers']:
                        for answer in dns_info['answers']:
                            print(f"[DNS] Answer: {{answer['name']}} -> {{answer['rdata']}}")

            # Parse ICMP
            elif ICMP in packet:
                self.statistics['icmp_packets'] += 1
                print(f"[ICMP] Type: {{packet[ICMP].type}}, Code: {{packet[ICMP].code}}")

            else:
                self.statistics['other_packets'] += 1

        # Display payload if verbose
        if self.verbose:
            payload = self.parse_payload(packet)
            if payload:
                print(f"\n[PAYLOAD] {{payload}}")

    def read_pcap(self) -> None:
        """Read and process packets from pcap file."""
        if not self.pcap_file.exists():
            print(f"Error: File not found: {{self.pcap_file}}", file=sys.stderr)
            sys.exit(1)

        try:
            print(f"Reading packets from: {{self.pcap_file}}")
            packets = rdpcap(str(self.pcap_file))
            print(f"Total packets in file: {{len(packets)}}\n")

            for packet in packets:
                self.process_packet(packet)

        except Exception as e:
            print(f"Error reading pcap file: {{e}}", file=sys.stderr)
            sys.exit(1)

    def print_statistics(self) -> None:
        """Print packet statistics."""
        print(f"\n{'='*80}")
        print("PACKET STATISTICS")
        print(f"{'='*80}")
        print(f"Total Packets:    {{self.statistics['total_packets']}}")
        print(f"IP Packets:       {{self.statistics['ip_packets']}}")
        print(f"TCP Packets:      {{self.statistics['tcp_packets']}}")
        print(f"UDP Packets:      {{self.statistics['udp_packets']}}")
        print(f"DNS Packets:      {{self.statistics['dns_packets']}}")
        print(f"HTTP Packets:     {{self.statistics['http_packets']}}")
        print(f"ICMP Packets:     {{self.statistics['icmp_packets']}}")
        print(f"Other Packets:    {{self.statistics['other_packets']}}")


def main():
    """Main entry point for the packet sniffer."""
    parser = argparse.ArgumentParser(
        description='Ethical Packet Sniffer - CTEC 450 Project',
        epilog='Example: python packet_sniffer.py capture.pcap --verbose --redact'
    )

    parser.add_argument(
        'pcap_file',
        help='Path to the pcap file to analyze'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (show packet payloads)'
    )

    parser.add_argument(
        '-r', '--redact',
        action='store_true',
        default=True,
        help='Enable sensitive data redaction (default: enabled)'
    )

    parser.add_argument(
        '--no-redact',
        action='store_false',
        dest='redact',
        help='Disable sensitive data redaction'
    )

    args = parser.parse_args()

    # Create and run sniffer
    sniffer = PacketSniffer(
        pcap_file=args.pcap_file,
        verbose=args.verbose,
        redact=args.redact
    )

    try:
        sniffer.read_pcap()
        sniffer.print_statistics()
    except KeyboardInterrupt:
        print("\n\nCapture interrupted by user.")
        sniffer.print_statistics()
        sys.exit(0)


if __name__ == '__main__':
    main()