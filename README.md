# recon

Network Reconnaissance Tool — built from scratch.

## Install

```bash
git clone https://github.com/og-arin/recon
cd recon
pip install .
```

That's it. `recon` is now a system command.

## Usage

```bash
# Single target
recon -t 192.168.1.1
recon -t google.com

# CIDR range
recon -r 192.168.1.0/24

# Custom ports
recon -t 192.168.1.1 -p 22,80,443
recon -t 192.168.1.1 -p 1-65535

# Export
recon -t 192.168.1.1 --export json
recon -t 192.168.1.1 --export pdf
recon -t 192.168.1.1 --export both

# Tune performance
recon -t 192.168.1.1 --threads 200 --timeout 0.5

# Interactive mode
recon -i
recon        # no args also drops into interactive
```

## Features

- TCP Connect scan (no root required)
- SYN stealth scan (root/admin required)
- OS fingerprinting via TTL analysis (root required)
- Banner grabbing
- Geo + ASN lookup
- Whois / RDAP
- Vuln hints for risky open ports
- JSON + PDF report export
- Threaded scanning for speed
- CIDR range support
- Cross-platform: Linux, macOS, Windows, Termux

## Requirements

- Python 3.10+
- `pip install colorama requests scapy fpdf2`

## Legal

Only scan systems you own or have explicit permission to test.
