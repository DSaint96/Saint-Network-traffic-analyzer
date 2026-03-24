# Sample PCAP Files

This folder holds `.pcap` files used to test the Network Traffic Analyzer.

## How to Generate Sample PCAPs

### Option 1: Capture Real Traffic with Wireshark
1. Open Wireshark
2. Select your network interface
3. Let it capture for 5-10 minutes of normal browsing
4. File → Save As → `normal_traffic.pcap`

### Option 2: Generate Simulated Attack Traffic with Scapy

Run the included generator script from the project root:

```bash
python generate_sample_pcap.py
```

This creates `sample_pcaps/sample_traffic.pcap` with a mix of:
- Normal HTTP/DNS traffic
- A simulated port scan
- Simulated brute force SSH attempts
- DNS tunneling-style queries

### Option 3: Use Public PCAP Datasets
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://malware-traffic-analysis.net/)
- [NETRESEC PCAP Files](https://www.netresec.com/?page=PcapFiles)
