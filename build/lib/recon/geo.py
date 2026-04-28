try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


def get_geo(ip: str) -> dict:
    if not REQUESTS_OK:
        return {"error": "requests not installed"}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,org,as,query"},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country":  data.get("country"),
                    "region":   data.get("regionName"),
                    "city":     data.get("city"),
                    "isp":      data.get("isp"),
                    "org":      data.get("org"),
                    "asn":      data.get("as"),
                }
    except Exception:
        pass
    return {"error": "Geo lookup failed"}


def get_whois(target: str) -> dict:
    if not REQUESTS_OK:
        return {"error": "requests not installed"}

    # Try domain RDAP first
    try:
        r = requests.get(f"https://rdap.org/domain/{target}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
            return {
                "type":         "domain",
                "registered":   events.get("registration", "N/A"),
                "last_changed": events.get("last changed", "N/A"),
                "expiry":       events.get("expiration", "N/A"),
                "status":       ", ".join(data.get("status", ["N/A"])),
            }
    except Exception:
        pass

    # Fallback: IP RDAP
    try:
        r = requests.get(f"https://rdap.org/ip/{target}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                "type":    "ip",
                "name":    data.get("name", "N/A"),
                "handle":  data.get("handle", "N/A"),
                "country": data.get("country", "N/A"),
            }
    except Exception:
        pass

    return {"error": "Whois lookup failed"}
