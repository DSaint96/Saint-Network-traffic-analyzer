#!/usr/bin/env python3
"""
Sample PCAP Generator
=====================
Generates a test .pcap file with simulated normal and malicious traffic.
This gives the analyzer something to detect without needing real captures.

Usage:
    python generate_sample_pcap.py

Output:
    sample_pcaps/sample_traffic.pcap
"""

import os
import random
import time
from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, Ether, RandShort, wrpcap
)


def generate_normal_traffic(base_time, count=200):
    """Generate normal-looking web browsing and DNS traffic."""
    packets = []
    normal_domains = [
        "www.google.com", "www.github.com", "docs.python.org",
        "stackoverflow.com", "www.youtube.com", "api.openai.com",
        "cdn.jsdelivr.net", "fonts.googleapis.com"
    ]
    
    for i in range(count):
        timestamp = base_time + random.uniform(0, 300)
        src_ip = f"192.168.1.{random.randint(10, 50)}"
        
        # Random DNS query
        if random.random() < 0.4:
            domain = random.choice(normal_domains)
            pkt = (
                IP(src=src_ip, dst="8.8.8.8") /
                UDP(sport=RandShort(), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=domain))
            )
        else:
            # Random HTTP-style TCP connection
            dst_ip = f"93.184.{random.randint(1, 255)}.{random.randint(1, 255)}"
            pkt = (
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=RandShort(), dport=random.choice([80, 443]), flags="S")
            )
        
        pkt.time = timestamp
        packets.append(pkt)
    
    return packets


def generate_port_scan(base_time):
    """Generate a simulated port scan — SYN packets to many ports."""
    packets = []
    attacker_ip = "192.168.1.105"
    target_ip = "10.0.0.50"
    
    # Scan 47 ports in about 12 seconds
    ports = random.sample(range(1, 1024), 47)
    
    for i, port in enumerate(ports):
        timestamp = base_time + 60 + (i * 0.25)  # ~4 ports per second
        pkt = (
            IP(src=attacker_ip, dst=target_ip) /
            TCP(sport=RandShort(), dport=port, flags="S")
        )
        pkt.time = timestamp
        packets.append(pkt)
    
    return packets


def generate_brute_force(base_time):
    """Generate simulated SSH brute force attempts."""
    packets = []
    attacker_ip = "203.0.113.77"
    target_ip = "10.0.0.10"
    
    # 83 SSH connection attempts in about 45 seconds
    for i in range(83):
        timestamp = base_time + 120 + (i * 0.55)
        pkt = (
            IP(src=attacker_ip, dst=target_ip) /
            TCP(sport=RandShort(), dport=22, flags="S")
        )
        pkt.time = timestamp
        packets.append(pkt)
    
    return packets


def generate_dns_tunneling(base_time):
    """Generate DNS queries that look like DNS tunneling."""
    packets = []
    attacker_ip = "192.168.1.42"
    
    # Long encoded-looking domain names
    tunneling_domains = [
        "aHR0cHM6Ly9leGFtcGxl.suspicious-domain.xyz",
        "dGhpcyBpcyBhIHRlc3Q.suspicious-domain.xyz",
        "c2VjcmV0IGRhdGEgZXhmaWx0cmF0aW9u.suspicious-domain.xyz",
        "bG9uZyBlbmNvZGVkIHN0cmluZyBoZXJl.data-exfil.top",
        "YW5vdGhlciBlbmNvZGVkIHBheWxvYWQ.data-exfil.top",
    ]
    
    for i, domain in enumerate(tunneling_domains):
        timestamp = base_time + 200 + (i * 2)
        pkt = (
            IP(src=attacker_ip, dst="8.8.8.8") /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = timestamp
        packets.append(pkt)
    
    return packets


def main():
    """Generate the complete sample PCAP file."""
    print("Generating sample PCAP with mixed traffic...")
    
    base_time = time.time() - 3600  # Start 1 hour ago
    
    all_packets = []
    
    print("  [+] Generating normal traffic (200 packets)...")
    all_packets.extend(generate_normal_traffic(base_time))
    
    print("  [+] Generating port scan traffic (47 packets)...")
    all_packets.extend(generate_port_scan(base_time))
    
    print("  [+] Generating brute force traffic (83 packets)...")
    all_packets.extend(generate_brute_force(base_time))
    
    print("  [+] Generating DNS tunneling traffic (5 packets)...")
    all_packets.extend(generate_dns_tunneling(base_time))
    
    # Sort all packets by timestamp
    all_packets.sort(key=lambda p: float(p.time))
    
    # Save to file
    output_dir = "sample_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sample_traffic.pcap")
    
    wrpcap(output_file, all_packets)
    
    print(f"\n  Total packets: {len(all_packets)}")
    print(f"  Saved to: {output_file}")
    print(f"\n  Run the analyzer:")
    print(f"    python analyzer.py {output_file}")


if __name__ == "__main__":
    main()
