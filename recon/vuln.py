RISKY_PORTS = {
    21:    "FTP — credentials sent in plaintext",
    23:    "Telnet — fully unencrypted protocol",
    25:    "SMTP — potential open relay",
    69:    "TFTP — no authentication",
    80:    "HTTP — unencrypted web traffic",
    111:   "RPCBind — exposure risk",
    135:   "MS-RPC — common lateral movement vector",
    139:   "NetBIOS — SMB/file share exposure",
    389:   "LDAP — potential for enumeration/credential attacks",
    445:   "SMB — check EternalBlue (MS17-010), PrintNightmare",
    512:   "rexec — plaintext remote execution",
    513:   "rlogin — plaintext remote login",
    514:   "rsh — no authentication",
    873:   "rsync — potential unauthorized file access",
    1080:  "SOCKS proxy — potential open proxy",
    1433:  "MSSQL — database exposed to network",
    1521:  "Oracle DB — database exposed to network",
    2049:  "NFS — filesystem may be accessible without auth",
    2375:  "Docker API — unauthenticated container access",
    2376:  "Docker API (TLS) — verify certificate enforcement",
    3306:  "MySQL — database exposed to network",
    3389:  "RDP — brute force / BlueKeep (CVE-2019-0708) candidate",
    4848:  "GlassFish Admin — default creds common",
    5432:  "PostgreSQL — database exposed to network",
    5900:  "VNC — remote desktop, often weak/no auth",
    5984:  "CouchDB — often unauthenticated",
    6379:  "Redis — commonly runs with no authentication",
    7001:  "WebLogic — known RCE vulnerabilities",
    8080:  "HTTP-alt — check for exposed admin panels",
    8443:  "HTTPS-alt — check for exposed admin panels",
    9200:  "Elasticsearch — often unauthenticated, data exposure",
    9300:  "Elasticsearch transport — cluster exposure",
    11211: "Memcached — no auth, amplification DDoS risk",
    27017: "MongoDB — commonly runs without authentication",
    50070: "Hadoop NameNode — data exposure",
    61616: "ActiveMQ — known deserialization RCE vulnerabilities",
}


def get_vuln_hints(open_ports: list[int]) -> list[dict]:
    return [
        {"port": p, "hint": RISKY_PORTS[p]}
        for p in open_ports if p in RISKY_PORTS
    ]
