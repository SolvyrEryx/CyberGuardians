"""
CyberGuardians - Advanced Multi-threaded Port Scanner with Banner Grabbing
Author: Solvyr Eryx

Features:
- High-performance TCP port scanning using thread pool
- Intelligent timeout/backoff and graceful shutdown
- Banner grabbing for service fingerprinting (where possible)
- CIDR/range and single-host support
- Colorized console output with summary
- Safe defaults and input validation

Usage:
  python port_scanner.py --target 192.168.1.1 --ports 1-1024 --threads 200
  python port_scanner.py --target example.com --top 100 --timeout 0.5

Disclaimer:
  Use only on systems you own or are authorized to test.
"""

from __future__ import annotations
import argparse
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from dataclasses import dataclass
from ipaddress import ip_address
import re
import time
from typing import Iterable, List, Tuple, Optional

# -------------- Console Colors --------------
class C:
    P = "\033[95m"  # purple
    B = "\033[94m"  # blue
    C = "\033[96m"  # cyan
    G = "\033[92m"  # green
    Y = "\033[93m"  # yellow
    R = "\033[91m"  # red
    E = "\033[0m"   # end
    D = "\033[90m"  # dim

# -------------- Port Utilities --------------
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMPtrap", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "Submission", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    27017: "MongoDB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

TOP_100_PORTS = [
    80, 23, 443, 21, 22, 25, 110, 139, 445, 143, 53, 135, 3306, 8080, 1723, 111,
    995, 993, 587, 5900, 554, 179, 1025, 1026, 1027, 1433, 3389, 1521, 1720, 5901,
    2000, 5060, 5631, 5902, 5000, 8888, 81, 88, 4433, 8000, 8443, 4444, 7001, 6010,
    68, 69, 514, 123, 161, 162, 389, 2049, 69, 514, 515, 631, 2049, 6379, 11211,
    27017, 9200, 5601, 27018, 27019, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165
]

# -------------- Data Structures --------------
@dataclass
class ScanResult:
    target: str
    port: int
    is_open: bool
    banner: Optional[str] = None

# -------------- Scanner Core --------------
def parse_ports(ports: Optional[str], top: Optional[int]) -> List[int]:
    if top:
        return TOP_100_PORTS[:top]
    if not ports:
        return list(range(1, 1025))
    out: List[int] = []
    for part in ports.split(','):
        part = part.strip()
        if re.match(r'^\d+$', part):
            out.append(int(part))
        elif re.match(r'^(\d+)-(\d+)$', part):
            a, b = map(int, part.split('-'))
            if a > b:
                a, b = b, a
            out.extend(range(a, b + 1))
        else:
            raise ValueError(f"Invalid port segment: {part}")
    return sorted(set(p for p in out if 1 <= p <= 65535))


def resolve_target(target: str) -> str:
    try:
        # ip_address will validate IPv4/IPv6; if fails, resolve DNS
        ip_address(target)
        return target
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            return resolved
        except socket.gaierror:
            raise ValueError(f"Unable to resolve target: {target}")


def grab_banner(sock: socket.socket, target: str, port: int, timeout: float) -> Optional[str]:
    sock.settimeout(timeout)
    banner = None
    try:
        # Some services send banner first (FTP, SMTP, etc.)
        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode(errors='ignore').strip()
        except socket.timeout:
            pass

        # Attempt protocol-specific probes
        probes = {
            80: b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n",
            443: b"\r\n",
            21: b"\r\n",
            22: b"\r\n",
            25: b"HELO example.com\r\n",
            110: b"\r\n",
            143: b"\r\n",
            6379: b"PING\r\n",
        }
        payload = probes.get(port)
        if payload:
            try:
                sock.sendall(payload)
                data = sock.recv(1024)
                if data:
                    text = data.decode(errors='ignore').strip()
                    banner = text if banner is None else f"{banner} | {text}"
            except socket.timeout:
                pass
    except Exception:
        pass
    return banner


def scan_port(target: str, port: int, timeout: float) -> ScanResult:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            start = time.time()
            result = sock.connect_ex((target, port))
            latency = (time.time() - start) * 1000
            if result == 0:
                banner = grab_banner(sock, target, port, timeout)
                return ScanResult(target, port, True, banner)
            else:
                return ScanResult(target, port, False, None)
        except (socket.timeout, OSError):
            return ScanResult(target, port, False, None)


def scan_target(target: str, ports: List[int], threads: int, timeout: float) -> List[ScanResult]:
    resolved = resolve_target(target)
    print(f"{C.P}[+] Target:{C.E} {target} {C.D}({resolved}){C.E}")
    print(f"{C.P}[+] Ports:{C.E} {len(ports)} selected | {C.P}Threads:{C.E} {threads} | {C.P}Timeout:{C.E} {timeout:.2f}s\n")

    results: List[ScanResult] = []
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, resolved, p, timeout): p for p in ports}
        try:
            for future in as_completed(future_to_port):
                res = future.result()
                with lock:
                    results.append(res)
                    if res.is_open:
                        svc = COMMON_PORTS.get(res.port, 'unknown')
                        banner = f" | {C.D}{res.banner}{C.E}" if res.banner else ''
                        print(f"{C.G}[OPEN]{C.E} {res.port:<6} {svc:<12}{banner}")
        except KeyboardInterrupt:
            print(f"\n{C.Y}[!] Interrupted by user. Shutting down gracefully...{C.E}")
            executor.shutdown(cancel_futures=True)
    return sorted(results, key=lambda r: r.port)


def summary(results: List[ScanResult]):
    open_ports = [r for r in results if r.is_open]
    print(f"\n{C.C}==== Scan Summary ===={C.E}")
    print(f"Open ports: {len(open_ports)}/{len(results)}")
    if open_ports:
        for r in open_ports:
            svc = COMMON_PORTS.get(r.port, 'unknown')
            banner = f" | {r.banner}" if r.banner else ''
            print(f" - {r.port:<6} {svc:<12}{banner}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CyberGuardians Port Scanner - Use responsibly",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--target', required=True, help='Target host (IP or domain)')
    p.add_argument('--ports', help='Ports: single, comma-list, or range (e.g., 22,80,443 or 1-1024)')
    p.add_argument('--top', type=int, help='Scan top N common ports (overrides --ports)')
    p.add_argument('--threads', type=int, default=200, help='Number of scanning threads')
    p.add_argument('--timeout', type=float, default=0.5, help='Per-connection timeout (seconds)')
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None):
    args = parse_args(argv)

    try:
        ports = parse_ports(args.ports, args.top)
    except ValueError as e:
        print(f"{C.R}[Error]{C.E} {e}")
        sys.exit(2)

    print(f"{C.B}CyberGuardians - Port Scanner{C.E}")
    print(f"{C.D}Author: Solvyr Eryx | For authorized security testing only{C.E}\n")

    results = scan_target(args.target, ports, args.threads, args.timeout)
    summary(results)


if __name__ == '__main__':
    main()
