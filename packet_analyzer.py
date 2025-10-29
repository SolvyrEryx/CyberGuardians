"""
CyberGuardians - Live Network Packet Analyzer

Description:
  A lightweight real-time packet analyzer using Scapy that captures HTTP traffic
  (default: TCP port 80) and prints request information in the console.

Features:
- Live capture on a specified network interface
- BPF filter support (e.g., "tcp port 80")
- Extracts and displays HTTP method, host, path, and user-agent when available
- Graceful Ctrl+C handling with capture summary

Usage:
  sudo python packet_analyzer.py --iface eth0 --filter "tcp port 80"

Requirements:
  - scapy

Install:
  pip install scapy

Legal Notice:
  Use only on networks you own or have explicit permission to monitor.
"""

from __future__ import annotations
import argparse
import signal
import sys
from datetime import datetime

try:
    from scapy.all import sniff, TCP, IP, Raw
except Exception as e:
    print("[!] Scapy is required. Install with: pip install scapy")
    raise


def parse_http_request(payload: bytes) -> dict:
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if not lines:
            return {}
        # Request line: METHOD PATH HTTP/1.1
        parts = lines[0].split()
        if len(parts) < 2:
            return {}
        method, path = parts[0], parts[1]
        headers = {"method": method, "path": path}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers
    except Exception:
        return {}


def pretty_http(headers: dict) -> str:
    method = headers.get("method", "?")
    host = headers.get("host", "?")
    path = headers.get("path", "/")
    ua = headers.get("user-agent", "-")
    return f"{method} http://{host}{path} | UA: {ua}"


def packet_handler(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        summary = f"[{ts}] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        if Raw in pkt:
            headers = parse_http_request(bytes(pkt[Raw]))
            if headers.get("method"):
                print(summary + " | " + pretty_http(headers))
            else:
                print(summary + " | Raw payload (non-HTTP)")
        else:
            print(summary)


def main():
    parser = argparse.ArgumentParser(description="Live network packet analyzer (HTTP focus)")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("--filter", type=str, default="tcp port 80", help="BPF filter for capture")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    args = parser.parse_args()

    print("CyberGuardians - Packet Analyzer")
    print("Press Ctrl+C to stop. Monitoring...\n")

    def stop_signal(signum, frame):
        print("\n[+] Stopping capture...")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_signal)

    sniff_kwargs = {"filter": args.filter, "prn": packet_handler, "count": args.count}
    if args.iface:
        sniff_kwargs["iface"] = args.iface

    sniff(**sniff_kwargs)


if __name__ == "__main__":
    main()
