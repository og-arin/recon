try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _G  = Fore.GREEN
    _B  = Style.BRIGHT
    _R  = Style.RESET_ALL
except ImportError:
    _G = _B = _R = ""


def g(text: str, bright: bool = False) -> str:
    return f"{_G}{_B if bright else ''}{text}{_R}"


def sep():
    print(g("─" * 62))


def print_banner():
    print(g(r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    """, bright=True))
    print(g("  [ Network Reconnaissance Tool ]", bright=True))
    print(g("  [ Author: Arin | Version: 1.0.0 ]\n"))


def print_root_status(root: bool):
    if root:
        print(g("  [+] Root/Admin — Full scan mode (SYN + OS fingerprint)\n", bright=True))
    else:
        print(g("  [!] No root/admin — TCP connect scan (SYN + OS fingerprint disabled)\n"))


def print_results(data: dict):
    sep()
    print(g(f"  TARGET : {data['target']}", bright=True))
    sep()

    # Host
    print(g("\n  [HOST]", bright=True))
    print(g(f"  IP Address    : {data.get('ip', 'N/A')}"))
    print(g(f"  Hostname      : {data.get('hostname') or 'N/A'}"))
    print(g(f"  Reverse DNS   : {data.get('reverse_dns') or 'N/A'}"))
    print(g(f"  Scan Type     : {data.get('scan_type', 'N/A')}"))

    os_info = data.get("os_fingerprint")
    if os_info:
        print(g(f"  OS Guess      : {os_info.get('os_guess')} (TTL {os_info.get('ttl')})"))

    # Geo
    geo = data.get("geo", {})
    if geo and not geo.get("error"):
        print(g("\n  [GEO / ASN]", bright=True))
        print(g(f"  Location      : {geo.get('city')}, {geo.get('region')}, {geo.get('country')}"))
        print(g(f"  ISP           : {geo.get('isp')}"))
        print(g(f"  Org           : {geo.get('org')}"))
        print(g(f"  ASN           : {geo.get('asn')}"))

    # Whois
    whois = data.get("whois", {})
    if whois and not whois.get("error"):
        print(g("\n  [WHOIS]", bright=True))
        for k, v in whois.items():
            if k != "type":
                label = k.replace("_", " ").capitalize()
                print(g(f"  {label:<14}: {v}"))

    # Ports
    open_ports = data.get("open_ports", [])
    if open_ports:
        print(g("\n  [OPEN PORTS & SERVICES]", bright=True))
        print(g(f"  {'PORT':<8} {'SERVICE':<16} {'BANNER'}"))
        print(g(f"  {'─'*6:<8} {'─'*14:<16} {'─'*30}"))
        services = data.get("services", {})
        banners  = data.get("banners", {})
        for port in open_ports:
            svc    = services.get(port, {})
            name   = svc.get("service", "unknown")
            banner = banners.get(port, "")[:50]
            print(g(f"  {port:<8} {name:<16} {banner}"))
    else:
        print(g("\n  [!] No open ports found"))

    # Vuln hints
    hints = data.get("vuln_hints", [])
    if hints:
        print(g("\n  [VULN HINTS]", bright=True))
        for h in hints:
            print(g(f"  [!] {h['port']:<6} — {h['hint']}"))
    else:
        print(g("\n  [+] No known risky ports detected"))

    sep()
    print(g(f"  Completed : {data.get('timestamp', 'N/A')}\n"))
