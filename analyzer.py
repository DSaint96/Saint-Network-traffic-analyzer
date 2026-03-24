#!/usr/bin/env python3
"""
Network Traffic Analyzer
========================
Reads .pcap files and detects suspicious network activity including
port scans, DNS anomalies, and brute force login attempts.

Usage:
    python analyzer.py <pcap_file> [--output reports/]

Author: Dennis Saint
"""

import sys
import os
from datetime import datetime
from scapy.all import rdpcap, IP

from detections import detect_port_scans, detect_dns_anomalies, detect_brute_force


def print_banner():
    """Print the tool banner."""
    print("=" * 61)
    print("  NETWORK TRAFFIC ANALYZER")
    print("  Automated Threat Detection Tool")
    print("=" * 61)


def get_packet_summary(packets):
    """Extract high-level stats from the packet capture."""
    total = len(packets)
    
    if total == 0:
        return {"total": 0, "start": "N/A", "end": "N/A", "unique_ips": 0}
    
    timestamps = [float(pkt.time) for pkt in packets]
    start_time = datetime.fromtimestamp(min(timestamps)).strftime("%Y-%m-%d %H:%M:%S")
    end_time = datetime.fromtimestamp(max(timestamps)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Count unique IPs
    unique_ips = set()
    for pkt in packets:
        if pkt.haslayer(IP):
            unique_ips.add(pkt[IP].src)
            unique_ips.add(pkt[IP].dst)
    
    return {
        "total": total,
        "start": start_time,
        "end": end_time,
        "unique_ips": len(unique_ips)
    }


def format_alert(alert):
    """Format a single alert for display."""
    lines = []
    severity_icon = "[!]" if alert["severity"] == "CRITICAL" else "[*]"
    
    if alert["type"] == "PORT_SCAN":
        lines.append(f"{severity_icon} PORT SCAN DETECTED")
        lines.append(f"    Source: {alert['source_ip']}")
        lines.append(f"    Target: {alert['target_ip']}")
        lines.append(f"    Ports scanned: {alert['ports_scanned']}")
        lines.append(f"    Duration: {alert['duration_seconds']} seconds")
        lines.append(f"    Sample ports: {alert['sample_ports']}")
    
    elif alert["type"] == "DNS_ANOMALY":
        lines.append(f"{severity_icon} DNS ANOMALY DETECTED")
        lines.append(f"    Source: {alert['source_ip']}")
        lines.append(f"    Query: {alert['query']}")
        lines.append(f"    Reason: {alert['reason']}")
    
    elif alert["type"] == "BRUTE_FORCE":
        lines.append(f"{severity_icon} BRUTE FORCE ATTEMPT DETECTED")
        lines.append(f"    Source: {alert['source_ip']}")
        lines.append(f"    Target: {alert['target_ip']}:{alert['target_port']} ({alert['service']})")
        lines.append(f"    Attempts: {alert['attempts']}")
        lines.append(f"    Duration: {alert['duration_seconds']} seconds")
    
    return "\n".join(lines)


def generate_report(pcap_file, summary, all_alerts, output_dir="reports"):
    """Save analysis report to a text file."""
    os.makedirs(output_dir, exist_ok=True)
    
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"report_{base_name}_{timestamp}.txt")
    
    with open(report_file, "w") as f:
        f.write("=" * 61 + "\n")
        f.write("  NETWORK TRAFFIC ANALYSIS REPORT\n")
        f.write("=" * 61 + "\n")
        f.write(f"  File: {os.path.basename(pcap_file)}\n")
        f.write(f"  Total Packets: {summary['total']:,}\n")
        f.write(f"  Unique IPs: {summary['unique_ips']}\n")
        f.write(f"  Time Range: {summary['start']} - {summary['end']}\n")
        f.write(f"  Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 61 + "\n\n")
        
        if not all_alerts:
            f.write("  No suspicious activity detected.\n\n")
        else:
            for alert in all_alerts:
                f.write(format_alert(alert) + "\n\n")
        
        # Summary counts
        critical = sum(1 for a in all_alerts if a["severity"] == "CRITICAL")
        warning = sum(1 for a in all_alerts if a["severity"] == "WARNING")
        
        f.write("-" * 61 + "\n")
        f.write(f"  SUMMARY: {len(all_alerts)} alerts generated | ")
        f.write(f"{critical} critical | {warning} warning\n")
        f.write("-" * 61 + "\n")
    
    return report_file


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <pcap_file> [--output reports/]")
        print("Example: python analyzer.py sample_pcaps/sample_traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_dir = "reports"
    
    # Parse optional output directory
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]
    
    # Validate file exists
    if not os.path.exists(pcap_file):
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    print_banner()
    print(f"\n  Loading: {pcap_file}")
    
    # Read packets
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        sys.exit(1)
    
    # Get summary
    summary = get_packet_summary(packets)
    print(f"  Packets loaded: {summary['total']:,}")
    print(f"  Unique IPs: {summary['unique_ips']}")
    print(f"  Time range: {summary['start']} - {summary['end']}")
    print(f"\n  Running detections...\n")
    
    # Run all detection modules
    all_alerts = []
    
    print("  [1/3] Scanning for port scans...")
    port_scan_alerts = detect_port_scans(packets)
    all_alerts.extend(port_scan_alerts)
    print(f"         Found: {len(port_scan_alerts)} alert(s)")
    
    print("  [2/3] Scanning for DNS anomalies...")
    dns_alerts = detect_dns_anomalies(packets)
    all_alerts.extend(dns_alerts)
    print(f"         Found: {len(dns_alerts)} alert(s)")
    
    print("  [3/3] Scanning for brute force attempts...")
    brute_alerts = detect_brute_force(packets)
    all_alerts.extend(brute_alerts)
    print(f"         Found: {len(brute_alerts)} alert(s)")
    
    # Display results
    print("\n" + "=" * 61)
    print("  RESULTS")
    print("=" * 61 + "\n")
    
    if not all_alerts:
        print("  No suspicious activity detected.\n")
    else:
        for alert in all_alerts:
            print(format_alert(alert))
            print()
    
    # Summary
    critical = sum(1 for a in all_alerts if a["severity"] == "CRITICAL")
    warning = sum(1 for a in all_alerts if a["severity"] == "WARNING")
    print("-" * 61)
    print(f"  SUMMARY: {len(all_alerts)} alerts | {critical} critical | {warning} warning")
    print("-" * 61)
    
    # Save report
    report_file = generate_report(pcap_file, summary, all_alerts, output_dir)
    print(f"\n  Report saved: {report_file}")
    print()


if __name__ == "__main__":
    main()
