import socket


# Probes per service to elicit banners
PROBES = {
    21:   b"",                              # FTP sends banner on connect
    22:   b"",                              # SSH sends banner on connect
    23:   b"",                              # Telnet sends banner on connect
    25:   b"EHLO recon\r\n",               # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP
    110:  b"",                              # POP3 sends banner on connect
    143:  b"",                              # IMAP sends banner on connect
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
    445:  b"",
    3306: b"",                              # MySQL sends banner on connect
    5432: b"",                              # PostgreSQL
    6379: b"INFO\r\n",                      # Redis
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    27017: b"",
}

DEFAULT_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        probe = PROBES.get(port, DEFAULT_PROBE)
        if probe:
            s.send(probe)

        raw = s.recv(1024)
        s.close()

        banner = raw.decode(errors="ignore").strip()
        if banner:
            # First line only, capped at 200 chars
            return banner.split("\n")[0].strip()[:200]
    except Exception:
        pass
    return None


def grab_all_banners(ip: str, open_ports: list[int]) -> dict[int, str]:
    banners = {}
    for port in open_ports:
        b = grab_banner(ip, port)
        if b:
            banners[port] = b
    return banners
