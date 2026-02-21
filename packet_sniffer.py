#!/usr/bin/env python3
import argparse
import re
import json
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

EMAIL_RE = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b")
AUTH_RE = re.compile(r"(?im)^authorization:\s*.*$")
COOKIE_RE = re.compile(r"(?im)^(cookie|set-cookie):\s*.*$")
QS_SECRET_RE = re.compile(r"(?i)(password|passwd|token|session)=([^&\s]+)")

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["xxx"])
    return ip

def redact(text: str) -> str:
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = AUTH_RE.sub("Authorization: [REDACTED]", text)
    text = COOKIE_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    text = QS_SECRET_RE.sub(r"\1=[REDACTED]", text)
    return text

def safe_decode(b: bytes, limit: int = 400) -> str:
    return redact(b[:limit].decode("utf-8", errors="ignore"))

def parse_http(payload: bytes):
    s = safe_decode(payload, limit=800)
    if not (s.startswith("GET ") or s.startswith("POST ") or s.startswith("PUT ") or s.startswith("DELETE ") or s.startswith("HEAD ")):
        return None
    lines = s.splitlines()
    req = lines[0].split()
    method = req[0] if len(req) > 0 else "UNKNOWN"
    path = req[1] if len(req) > 1 else "UNKNOWN"
    host = "UNKNOWN"
    for line in lines[1:40]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return {"method": method, "host": redact(host), "path": redact(path)}

def main():
    parser = argparse.ArgumentParser(description="Ethical Packet Sniffer (PCAP-only, Scapy)")
    parser.add_argument("--pcap", required=True, help="Path to .pcap file")
    parser.add_argument("--count", type=int, default=25, help="Number of packets to process (default 25)")
    parser.add_argument("--verbose", action="store_true", help="Show redacted payload preview")
    args = parser.parse_args()

    packets = rdpcap(args.pcap)
    stats = {"total": 0, "ip": 0, "tcp": 0, "udp": 0, "dns": 0, "http": 0}

    for i, pkt in enumerate(packets[:args.count], start=1):
        if IP not in pkt:
            continue

        stats["total"] += 1
        stats["ip"] += 1

        record = {
            "packet": i,
            "src_ip": mask_ip(pkt[IP].src),
            "dst_ip": mask_ip(pkt[IP].dst),
            "len": len(pkt),
        }

        if TCP in pkt:
            stats["tcp"] += 1
            record["proto"] = "TCP"
            record["src_port"] = int(pkt[TCP].sport)
            record["dst_port"] = int(pkt[TCP].dport)

            if Raw in pkt:
                http = parse_http(bytes(pkt[Raw].load))
                if http:
                    stats["http"] += 1
                    record["http"] = http

        elif UDP in pkt:
            stats["udp"] += 1
            record["proto"] = "UDP"
            record["src_port"] = int(pkt[UDP].sport)
            record["dst_port"] = int(pkt[UDP].dport)

            if DNS in pkt and pkt[DNS].qd and DNSQR in pkt:
                qname = pkt[DNS][DNSQR].qname.decode(errors="ignore").rstrip(".")
                record["dns_query"] = redact(qname)
                stats["dns"] += 1

        print(json.dumps(record, ensure_ascii=False))

        if args.verbose and Raw in pkt:
            print("PAYLOAD:", safe_decode(bytes(pkt[Raw].load)))

    print("\nSTATS:", json.dumps(stats, ensure_ascii=False))

if __name__ == "__main__":
    main()
        
   
