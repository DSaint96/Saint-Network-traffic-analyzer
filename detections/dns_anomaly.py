"""
DNS Anomaly Detection Module
Detects suspicious DNS activity including:
- Unusually long domain queries (potential DNS tunneling)
- High-frequency DNS requests from a single host
- Queries to known suspicious TLDs
"""

from collections import defaultdict
from scapy.all import DNS, DNSQR


# TLDs commonly associated with malicious activity
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".club", ".work", ".loan",
    ".click", ".gdn", ".racing", ".review", ".country",
    ".stream", ".download", ".xin", ".bid", ".party"
}

# Domain length threshold for tunneling detection
DOMAIN_LENGTH_THRESHOLD = 50

# High frequency threshold: queries per minute from a single host
FREQUENCY_THRESHOLD = 60


def detect_dns_anomalies(packets, domain_len_threshold=DOMAIN_LENGTH_THRESHOLD,
                          freq_threshold=FREQUENCY_THRESHOLD):
    """
    Analyze packets for suspicious DNS activity.
    
    Args:
        packets: List of Scapy packet objects
        domain_len_threshold: Max normal domain length (default: 50)
        freq_threshold: Max normal queries per minute (default: 60)
    
    Returns:
        List of dicts containing anomaly details
    """
    alerts = []
    dns_queries_by_host = defaultdict(list)
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dns = pkt[DNS]
            
            # Only look at DNS queries (not responses)
            if dns.qr == 0:
                query_name = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                src_ip = pkt.sprintf("%IP.src%")
                timestamp = float(pkt.time)
                
                dns_queries_by_host[src_ip].append({
                    "query": query_name,
                    "timestamp": timestamp
                })
                
                # Check 1: Unusually long domain name (DNS tunneling indicator)
                if len(query_name) > domain_len_threshold:
                    alerts.append({
                        "type": "DNS_ANOMALY",
                        "severity": "WARNING",
                        "source_ip": src_ip,
                        "query": query_name,
                        "reason": f"Domain length ({len(query_name)} chars) exceeds "
                                  f"threshold — possible DNS tunneling"
                    })
                
                # Check 2: Suspicious TLD
                for tld in SUSPICIOUS_TLDS:
                    if query_name.endswith(tld.lstrip(".")):
                        alerts.append({
                            "type": "DNS_ANOMALY",
                            "severity": "WARNING",
                            "source_ip": src_ip,
                            "query": query_name,
                            "reason": f"Query to suspicious TLD: {tld}"
                        })
                        break
    
    # Check 3: High-frequency DNS requests from a single host
    for src_ip, queries in dns_queries_by_host.items():
        if len(queries) < 2:
            continue
        
        timestamps = sorted([q["timestamp"] for q in queries])
        duration_minutes = (timestamps[-1] - timestamps[0]) / 60
        
        if duration_minutes > 0:
            queries_per_minute = len(queries) / duration_minutes
            
            if queries_per_minute > freq_threshold:
                alerts.append({
                    "type": "DNS_ANOMALY",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "query": f"{len(queries)} total queries",
                    "reason": f"High-frequency DNS: {queries_per_minute:.0f} queries/min "
                              f"(threshold: {freq_threshold}/min)"
                })
    
    return alerts
