"""
Port Scan Detection Module
Detects hosts sending SYN packets to multiple ports on a single target.
Threshold: 20+ unique ports within a 60-second window.
"""

from collections import defaultdict
from scapy.all import TCP


def detect_port_scans(packets, port_threshold=20, time_window=60):
    """
    Analyze packets for port scan activity.
    
    Args:
        packets: List of Scapy packet objects
        port_threshold: Minimum unique ports to flag as scan (default: 20)
        time_window: Time window in seconds to group activity (default: 60)
    
    Returns:
        List of dicts containing scan details
    """
    # Track connections: (source_ip, target_ip) -> {ports, timestamps}
    connections = defaultdict(lambda: {"ports": set(), "timestamps": []})
    
    for pkt in packets:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # Look for SYN packets — the first step of a connection
            if tcp.flags == "S":
                src_ip = pkt.sprintf("%IP.src%")
                dst_ip = pkt.sprintf("%IP.dst%")
                dst_port = tcp.dport
                timestamp = float(pkt.time)
                
                key = (src_ip, dst_ip)
                connections[key]["ports"].add(dst_port)
                connections[key]["timestamps"].append(timestamp)
    
    # Analyze for scans
    alerts = []
    for (src_ip, dst_ip), data in connections.items():
        if len(data["ports"]) >= port_threshold:
            timestamps = sorted(data["timestamps"])
            duration = timestamps[-1] - timestamps[0]

            # Check if activity falls within the time window
            if duration <= time_window:
                from datetime import datetime
                alerts.append({
                    "type": "PORT_SCAN",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "ports_scanned": len(data["ports"]),
                    "duration_seconds": round(duration, 1),
                    "sample_ports": sorted(list(data["ports"]))[:10],
                    "first_seen": datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S"),
                })
    
    return alerts
