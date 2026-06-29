# CodeAlpha_NIDS
# 🛡️ Network Intrusion Detection System (NIDS)

> **CodeAlpha Cybersecurity Internship – Task 4**  
> A Python-based NIDS that monitors network traffic in real-time, detects attacks using custom rules, logs alerts, implements response mechanisms, and visualizes detected threats.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Detection Rules](#detection-rules)
- [Installation](#installation)
- [Usage](#usage)
- [Demo Mode](#demo-mode)
- [Output & Reports](#output--reports)
- [How It Works](#how-it-works)
- [Screenshots](#screenshots)
- [Technologies Used](#technologies-used)

---

## Overview

This Network Intrusion Detection System (NIDS) is a network-based security tool that passively monitors traffic on a selected interface, applies signature-based and behavioral detection rules, and raises alerts when suspicious or malicious activity is found.

It fulfills all five requirements of CodeAlpha Task 4:

| Requirement | Implementation |
|---|---|
| Set up a network-based IDS | Scapy packet sniffer on any interface |
| Configure rules and alerts | 15+ detection rules across 5 categories |
| Monitor traffic continuously | Multi-threaded sniffing with timeout control |
| Implement response mechanisms | Auto-block via iptables (Linux) / Windows guidance |
| Visualize detected attacks | matplotlib charts + full HTML report |

---

## Features

- **Real-time packet capture** using Scapy on any network interface
- **5 detection categories**: Port Scan, SYN Flood, ICMP Flood, Suspicious Ports, Malicious Payloads
- **15+ payload signatures**: SQL injection, XSS, directory traversal, reverse shells, PowerShell, and more
- **Severity levels**: CRITICAL / HIGH / MEDIUM / LOW with colour-coded console output
- **Auto-block response**: iptables integration to block attacking IPs in real-time (Linux)
- **JSON alert logging** for audit trails and SIEM integration
- **HTML report** with statistics, alert table, severity pie chart, and threat-type bar chart
- **Demo mode** – runs without a live interface using simulated attack traffic
- **10 unit tests** covering all major detection rules

---

## Project Structure

```
NIDS/
├── nids.py                    # Main NIDS engine
├── test_nids.py               # Unit tests + sample report generator
├── requirements.txt           # Python dependencies
├── rules/
│   └── detection_rules.rules  # Human-readable rule definitions
├── logs/
│   └── alerts.json            # Generated alert log (JSONL format)
└── reports/
    ├── report.html            # Generated HTML report
    └── attack_chart.png       # Generated charts
```

---

## Detection Rules

### 1. Port Scan Detection
Fires when a single source IP contacts **10 or more unique destination ports within 5 seconds**.

### 2. SYN Flood (DoS)
Fires when a source sends **50+ TCP SYN-only packets per second** — a classic denial-of-service technique.

### 3. ICMP Flood (Ping Flood)
Fires when a source sends **30+ ICMP packets per second**.

### 4. Suspicious Port Access
Alerts on traffic to well-known attack/pivot ports:

| Port | Service | Risk |
|------|---------|------|
| 23 | Telnet | Plaintext credentials |
| 445 | SMB | EternalBlue / WannaCry |
| 3389 | RDP | Brute-force target |
| 4444 | Metasploit | Default listener |
| 5900 | VNC | Remote access |
| 6667 | IRC | C2 channel |

### 5. Malicious Payload Signatures

| Signature | Threat |
|-----------|--------|
| `UNION SELECT` | SQL Injection |
| `<script>` | XSS |
| `../` | Directory Traversal |
| `/etc/passwd` | LFI |
| `cmd.exe`, `powershell` | Shell execution |
| `nc -e` | Netcat reverse shell |
| `wget http`, `curl http` | Remote file download |
| `base64` | Payload obfuscation |

---

## Installation

### Prerequisites
- Python 3.8+
- **Linux**: run as root (`sudo`)
- **Windows**: install [Npcap](https://npcap.com) first, then run as Administrator

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/CodeAlpha_ProjectName.git
cd CodeAlpha_ProjectName/NIDS

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Quick Start – Demo Mode (no root/interface needed)
```bash
python nids.py --demo
```

### Live Network Monitoring
```bash
# Linux (requires root)
sudo python nids.py -i eth0 -t 120

# Windows (requires Admin + Npcap)
python nids.py -i "Wi-Fi" -t 120
```

### All Options

```
usage: nids.py [-h] [-i INTERFACE] [-t TIMEOUT] [--demo] [--auto-block]
               [--report] [--log LOG] [--no-verbose]

options:
  -h, --help            Show this help and exit
  -i, --interface       Network interface (e.g. eth0, Wi-Fi)
  -t, --timeout         Capture duration in seconds (default: 60)
  --demo                Run with simulated attack traffic
  --auto-block          Auto-block CRITICAL IPs via iptables (Linux + root)
  --report              Generate HTML report after session (default: on)
  --log LOG             JSON alert log path (default: logs/alerts.json)
  --no-verbose          Suppress real-time console alerts
```

### Examples

```bash
# 5-minute capture on eth0 with auto-blocking
sudo python nids.py -i eth0 -t 300 --auto-block

# Quiet mode – log only, no console output
sudo python nids.py -i eth0 --no-verbose

# Run unit tests
python test_nids.py
```

---

## Demo Mode

The `--demo` flag runs 9 simulated attack scenarios without requiring a network interface or root privileges:

| Scenario | Attack Type |
|----------|-------------|
| Port scan from 10.0.0.1 | Port Scan |
| SYN flood from 10.0.0.2 | DoS |
| Telnet access | Suspicious Port |
| SQL injection payload | Malicious Payload |
| ICMP flood | Ping Flood |
| Metasploit port (4444) | Suspicious Port |
| PowerShell payload | Malicious Payload |
| Netcat reverse shell | Malicious Payload |
| RDP connection | Suspicious Port |

---

## Output & Reports

### Console Output (real-time)
```
  [14:23:01] [CRITICAL] SYN Flood (DoS) — 10.0.0.2 sent 50+ SYN packets in 1s
  [14:23:01] [HIGH]     Port Scan — 10.0.0.1 scanned 10+ ports in 5s
  [14:23:02] [CRITICAL] Malicious Payload — SQL Injection detected from 10.0.0.4
```

### JSON Alert Log (`logs/alerts.json`)
```json
{"threat_type": "SYN Flood (DoS)", "severity": "CRITICAL", "src": "10.0.0.2", "dst": "192.168.1.1", "description": "...", "timestamp": "2025-01-01T14:23:01.123456"}
```

### HTML Report (`reports/report.html`)
- Summary statistics (total, critical, high, medium, low)
- Severity breakdown pie chart
- Threat type bar chart
- Full alert table with timestamps, IPs, and descriptions

---

## How It Works

```
Network Interface
      │
      ▼
  Scapy Sniffer  ──► packet_callback()
                          │
                          ▼
                   DetectionRules.analyze()
                    ├── Port Scan check
                    ├── SYN Flood check
                    ├── ICMP Flood check
                    ├── Suspicious Port check
                    └── Payload Signature check
                          │
                    Alert raised?
                    ├── YES ──► AlertManager.record()
                    │              ├── Console output (colour-coded)
                    │              └── JSON log file
                    │          ResponseEngine.respond()
                    │              └── iptables block (if CRITICAL + --auto-block)
                    └── NO  ──► packet discarded
                          │
               On exit ──► generate_report()
                              ├── matplotlib charts (PNG)
                              └── HTML report
```

---

## Technologies Used

| Tool | Purpose |
|------|---------|
| **Python 3** | Core language |
| **Scapy** | Packet capture and analysis |
| **matplotlib** | Chart generation (pie + bar) |
| **iptables** | Automated IP blocking (Linux) |
| **HTML/CSS** | Report generation (dark theme) |
| **JSON** | Alert logging format |

---

## Author

**Abel** – CodeAlpha Cybersecurity Intern  
📍 Mekelle, Tigray, Ethiopia  
🔗 [LinkedIn](https://linkedin.com) | [GitHub](https://github.com)

---

## License

This project is built for educational purposes as part of the CodeAlpha Cybersecurity Internship.

---

*"Security is not a product, but a process." – Bruce Schneier*
