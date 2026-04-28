import socket


def resolve(target: str) -> dict:
    result = {
        "target": target,
        "ip": None,
        "hostname": None,
        "reverse_dns": None,
        "error": None
    }
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
        # if input was a domain, store it as hostname
        result["hostname"] = target if not _is_ip(target) else None
        # reverse DNS
        try:
            result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            result["reverse_dns"] = "N/A"
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except socket.error:
        return False
