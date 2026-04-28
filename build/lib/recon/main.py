import sys
import ipaddress
import argparse
from datetime import datetime

from .resolver import resolve
from .scanner  import scan_ports, os_fingerprint, is_root, TOP_1000_PORTS
from .banner   import grab_all_banners
from .geo      import get_geo, get_whois
from .vuln     import get_vuln_hints
from .output   import g, print_banner, print_root_status, print_results
from .report   import export_json, export_pdf, build_filename


# ─────────────────────────────────────────────
#  CORE
# ─────────────────────────────────────────────

def scan(target: str, ports: list[int], threads: int, timeout: float) -> dict | None:
    print(g(f"\n  [*] Target: {target}", bright=True))

    host = resolve(target)
    if host.get("error") or not host.get("ip"):
        print(g(f"  [!] Could not resolve {target} — {host.get('error', 'unknown error')}"))
        return None

    ip = host["ip"]
    print(g(f"  [*] Resolved → {ip}"))

    data = {
        "target":    target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **host
    }

    # Geo + Whois
    print(g("  [*] Fetching geo / whois..."))
    data["geo"]   = get_geo(ip)
    data["whois"] = get_whois(target)

    # Port scan
    print(g(f"  [*] Scanning {len(ports)} ports ({threads} threads)..."))
    scan_result = scan_ports(ip, ports=ports, threads=threads, timeout=timeout)
    data["open_ports"] = scan_result["open_ports"]
    data["services"]   = scan_result["services"]
    data["scan_type"]  = scan_result["scan_type"]
    print(g(f"  [+] {len(data['open_ports'])} open port(s) found"))

    # OS fingerprint (root only)
    if is_root():
        print(g("  [*] OS fingerprinting..."))
        data["os_fingerprint"] = os_fingerprint(ip)
    else:
        data["os_fingerprint"] = None

    # Banner grab
    if data["open_ports"]:
        print(g("  [*] Grabbing banners..."))
        data["banners"] = grab_all_banners(ip, data["open_ports"])
    else:
        data["banners"] = {}

    # Vuln hints
    data["vuln_hints"] = get_vuln_hints(data["open_ports"])

    return data


def handle_export(results: list[dict], export: str):
    if not results:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if export in ("json", "both"):
        payload = results[0] if len(results) == 1 else results
        fname   = f"recon_{ts}.json"
        export_json(payload, fname)

    if export in ("pdf", "both"):
        for d in results:
            fname = build_filename(d["target"], "pdf")
            export_pdf(d, fname)


def run(targets: list[str], ports: list[int], threads: int, timeout: float, export: str):
    results = []
    for t in targets:
        data = scan(t, ports, threads, timeout)
        if data:
            print_results(data)
            results.append(data)
    handle_export(results, export)


# ─────────────────────────────────────────────
#  INTERACTIVE
# ─────────────────────────────────────────────

def interactive(default_ports: list[int], threads: int, timeout: float):
    while True:
        print(g("\n  [1] Single target"))
        print(g("  [2] CIDR range"))
        print(g("  [3] Exit\n"))
        choice = input(g("  recon > ")).strip()

        if choice == "1":
            target = input(g("  Target (IP or domain) : ")).strip()
            ports  = _ask_ports(default_ports)
            export = input(g("  Export [json/pdf/both/no] : ")).strip().lower()
            run([target], ports, threads, timeout, export)

        elif choice == "2":
            cidr   = input(g("  CIDR range (e.g. 192.168.1.0/24) : ")).strip()
            ports  = _ask_ports(default_ports)
            export = input(g("  Export [json/pdf/both/no] : ")).strip().lower()
            try:
                targets = [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False).hosts()]
                print(g(f"  [*] {len(targets)} hosts queued"))
                run(targets, ports, threads, timeout, export)
            except ValueError as e:
                print(g(f"  [!] Invalid CIDR: {e}"))

        elif choice == "3":
            print(g("  [*] Exiting recon. Stay safe.\n"))
            sys.exit(0)
        else:
            print(g("  [!] Invalid choice"))


def _ask_ports(default_ports: list[int]) -> list[int]:
    ans = input(g("  Port range [default top-1000 / custom e.g. 1-65535 / list e.g. 22,80,443] : ")).strip()
    if not ans or ans.lower() == "default":
        return default_ports
    return _parse_ports(ans)


def _parse_ports(spec: str) -> list[int]:
    """Parse port spec: range '1-1024', list '22,80,443', or single '80'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(ports)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def cli():
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Network Reconnaissance Tool — by Arin",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",
        help="Single target IP or domain")
    parser.add_argument("-r", "--range",
        help="CIDR range  (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",
        help="Port spec   (e.g. 80, 1-1024, 22,80,443) — default: top 1000",
        default=None)
    parser.add_argument("--threads",
        type=int, default=100,
        help="Thread count (default: 100)")
    parser.add_argument("--timeout",
        type=float, default=1.0,
        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--export",
        choices=["json", "pdf", "both", "no"], default="no",
        help="Export format (default: no)")
    parser.add_argument("-i", "--interactive",
        action="store_true",
        help="Interactive mode")

    args = parser.parse_args()

    print_banner()
    print_root_status(is_root())

    # Resolve port list
    if args.ports:
        ports = _parse_ports(args.ports)
    else:
        ports = TOP_1000_PORTS

    # No args → interactive
    if args.interactive or (not args.target and not args.range):
        interactive(ports, args.threads, args.timeout)
        return

    targets = []

    if args.target:
        targets.append(args.target)

    if args.range:
        try:
            targets = [str(ip) for ip in ipaddress.IPv4Network(args.range, strict=False).hosts()]
            print(g(f"  [*] {len(targets)} hosts in range"))
        except ValueError as e:
            print(g(f"  [!] Invalid CIDR: {e}"))
            sys.exit(1)

    run(targets, ports, args.threads, args.timeout, args.export)
