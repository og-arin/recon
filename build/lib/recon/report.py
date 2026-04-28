import json
from datetime import datetime

try:
    from fpdf import FPDF
    FPDF_OK = True
except ImportError:
    FPDF_OK = False

try:
    from colorama import Fore, Style
    G = Fore.GREEN
    R = Style.RESET_ALL
except ImportError:
    G = R = ""


def _g(t): return f"{G}{t}{R}"


def export_json(data: dict | list, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(_g(f"  [+] JSON saved → {path}"))


def export_pdf(data: dict, path: str):
    if not FPDF_OK:
        print(_g("  [!] fpdf2 not installed — skipping PDF"))
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=10)
    pdf.set_text_color(0, 180, 0)

    def ln(text=""):
        pdf.multi_cell(0, 6, str(text))

    ln(f"RECON REPORT")
    ln(f"Target    : {data.get('target')}")
    ln(f"Generated : {data.get('timestamp')}")
    ln("=" * 65)

    ln(f"IP        : {data.get('ip', 'N/A')}")
    ln(f"Hostname  : {data.get('hostname') or 'N/A'}")
    ln(f"Rev DNS   : {data.get('reverse_dns') or 'N/A'}")
    ln(f"Scan Type : {data.get('scan_type', 'N/A')}")

    os_info = data.get("os_fingerprint")
    if os_info:
        ln(f"OS Guess  : {os_info.get('os_guess')} (TTL {os_info.get('ttl')})")

    geo = data.get("geo", {})
    if geo and not geo.get("error"):
        ln()
        ln("[GEO / ASN]")
        ln(f"Location  : {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
        ln(f"ISP       : {geo.get('isp')}")
        ln(f"ASN       : {geo.get('asn')}")

    whois = data.get("whois", {})
    if whois and not whois.get("error"):
        ln()
        ln("[WHOIS]")
        for k, v in whois.items():
            if k != "type":
                ln(f"  {k.replace('_',' ').capitalize():<14}: {v}")

    open_ports = data.get("open_ports", [])
    if open_ports:
        ln()
        ln("[OPEN PORTS]")
        services = data.get("services", {})
        banners  = data.get("banners", {})
        ln(f"  {'PORT':<8} {'SERVICE':<16} BANNER")
        for port in open_ports:
            svc    = services.get(port, {})
            name   = svc.get("service", "unknown")
            banner = banners.get(port, "")[:60]
            ln(f"  {port:<8} {name:<16} {banner}")

    hints = data.get("vuln_hints", [])
    if hints:
        ln()
        ln("[VULN HINTS]")
        for h in hints:
            ln(f"  [!] Port {h['port']} — {h['hint']}")

    pdf.output(path)
    print(_g(f"  [+] PDF saved  → {path}"))


def build_filename(target: str, ext: str) -> str:
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean  = target.replace(".", "_").replace("/", "_")
    return f"recon_{clean}_{ts}.{ext}"
