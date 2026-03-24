# Network Traffic Analyzer

A Python-based network traffic analysis tool that reads `.pcap` (packet capture) files and automatically detects suspicious activity — including port scans, DNS anomalies, and brute force login attempts. Designed to simulate the type of threat detection work performed by SOC Analysts in real-world security operations centers.

## Why I Built This

As part of my transition into cybersecurity, I wanted to demonstrate practical skills in network analysis, Python scripting, and threat detection logic — the core of what a SOC Analyst does every day. This tool automates the initial triage process that analysts perform when reviewing captured network traffic.

## What It Detects

- **Port Scans** — Identifies hosts sending SYN packets to multiple ports on a single target within a short time window (threshold: 20+ ports in 60 seconds)
- **DNS Anomalies** — Flags unusually long domain queries (potential DNS tunneling), high-frequency DNS requests from a single host, and queries to known suspicious TLDs
- **Brute Force Attempts** — Detects repeated failed connection attempts to common authentication ports (SSH/22, RDP/3389, FTP/21) from the same source IP

## Tools & Technologies

- **Python 3.10+**
- **Scapy** — Packet parsing and protocol analysis
- **Wireshark** — Used to generate sample PCAP files for testing
- **Matplotlib** (optional) — Visual summary charts

## Project Structure

```
network-traffic-analyzer/
├── README.md                 # Project documentation (you're here)
├── requirements.txt          # Python dependencies
├── analyzer.py               # Main script — runs all detections
├── detections/
│   ├── __init__.py
│   ├── port_scan.py          # Port scan detection module
│   ├── dns_anomaly.py        # DNS anomaly detection module
│   └── brute_force.py        # Brute force detection module
├── sample_pcaps/             # Sample .pcap files for testing
│   └── README.md             # Instructions for generating test PCAPs
├── reports/                  # Generated analysis reports
└── screenshots/              # Terminal output for documentation
```

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/DSaint96/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the analyzer
```bash
python analyzer.py sample_pcaps/sample_traffic.pcap
```

### 4. View the report
After running, check the `reports/` folder for the generated analysis report.

## Sample Output

```
=============================================================
  NETWORK TRAFFIC ANALYSIS REPORT
=============================================================
  File: sample_traffic.pcap
  Total Packets: 14,832
  Time Range: 2026-03-20 08:15:22 - 2026-03-20 09:42:18
=============================================================

[!] PORT SCAN DETECTED
    Source: 192.168.1.105
    Target: 10.0.0.50
    Ports scanned: 47
    Duration: 12.4 seconds

[!] DNS ANOMALY DETECTED
    Source: 192.168.1.42
    Query: aHR0cHM6Ly9leGFtcGxl.suspicious-domain.xyz
    Reason: Domain length exceeds threshold (possible DNS tunneling)

[!] BRUTE FORCE ATTEMPT DETECTED
    Source: 203.0.113.77
    Target: 10.0.0.10:22 (SSH)
    Attempts: 83
    Duration: 45.2 seconds

-------------------------------------------------------------
  SUMMARY: 3 alerts generated | 2 critical | 1 warning
-------------------------------------------------------------
```

## Lessons Learned

- **Scapy's packet parsing** requires understanding of network protocol layers — I had to learn how TCP flags, DNS query structures, and connection states work at the packet level
- **Threshold tuning** is critical — too sensitive and you get false positives, too loose and real threats slip through. This mirrors the alert fatigue challenge SOC Analysts face daily
- **Writing detection logic** helped me understand how commercial SIEM/IDS tools like Splunk and Snort work under the hood

## Future Improvements

- [ ] Add GeoIP lookup for flagged external IPs
- [ ] Export reports to PDF format
- [ ] Integrate with VirusTotal API for domain reputation checks
- [ ] Add ICMP flood / ping sweep detection
- [ ] Build a simple dashboard to visualize findings

## Author

**Dennis Saint**
Cybersecurity student & aspiring SOC Analyst
[GitHub](https://github.com/DSaint96) | [LinkedIn](https://linkedin.com/in/YOUR_LINKEDIN)

## License

This project is for educational and portfolio purposes.
