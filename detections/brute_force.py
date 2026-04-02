"""
Brute Force Detection Module
Detects repeated connection attempts to authentication ports from the same source.
Monitored ports: SSH (22), RDP (3389), FTP (21), Telnet (23), SMTP (25)
"""

from collections import defaultdict
from scapy.all import TCP


# Ports commonly targeted in brute force attacks
AUTH_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    25: "SMTP",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

# Threshold: connections to same port from same source
ATTEMPT_THRESHOLD = 10

# Time window in seconds
TIME_WINDOW = 120


def detect_brute_force(packets, attempt_threshold=ATTEMPT_THRESHOLD,
                        time_window=TIME_WINDOW):
    """
    Analyze packets for brute force login attempts.
    
    Args:
        packets: List of Scapy packet objects
        attempt_threshold: Min connection attempts to flag (default: 10)
        time_window: Time window in seconds (default: 120)
    
    Returns:
        List of dicts containing brute force details
    """
    # Track: (source_ip, target_ip, target_port) -> [timestamps]
    connection_attempts = defaultdict(list)
    
    for pkt in packets:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_port = tcp.dport
            
            # Only monitor authentication-related ports
            if dst_port in AUTH_PORTS:
                # SYN packets indicate new connection attempts
                if tcp.flags == "S":
                    src_ip = pkt.sprintf("%IP.src%")
                    dst_ip = pkt.sprintf("%IP.dst%")
                    timestamp = float(pkt.time)
                    
                    key = (src_ip, dst_ip, dst_port)
                    connection_attempts[key].append(timestamp)
    
    # Analyze for brute force patterns
    alerts = []
    for (src_ip, dst_ip, dst_port), timestamps in connection_attempts.items():
        if len(timestamps) >= attempt_threshold:
            sorted_times = sorted(timestamps)
            duration = sorted_times[-1] - sorted_times[0]

            if duration <= time_window:
                service = AUTH_PORTS.get(dst_port, "Unknown")

                # Determine severity based on attempt count
                if len(timestamps) >= 50:
                    severity = "CRITICAL"
                else:
                    severity = "WARNING"

                from datetime import datetime
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": severity,
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "service": service,
                    "attempts": len(timestamps),
                    "duration_seconds": round(duration, 1),
                    "first_seen": datetime.fromtimestamp(sorted_times[0]).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.fromtimestamp(sorted_times[-1]).strftime("%Y-%m-%d %H:%M:%S"),
                })
    
    return alerts
