# VulnScanner CLI (Ubuntu)

A lightweight, educational vulnerability scanner for college projects.

## Features

- Network scan:
  - Checks common/open ports
  - Fast threaded scan with configurable workers
  - Grabs basic service banners
  - Detects risky exposed services (e.g., Telnet/DB ports)
  - Flags suspicious banner signatures/version disclosure
  - TLS certificate expiry check (for HTTPS services)
- LAN scan:
  - Auto-detects local Wi-Fi/LAN subnet (or accepts manual CIDR)
  - Discovers live hosts in subnet
  - Scans configured ports on each discovered host
  - Optional reverse-DNS labeling
  - Optional OS fingerprinting with `nmap` (`--os-detect`)
- Web scan:
  - Checks for missing important HTTP security headers
  - Checks dangerous HTTP methods via `OPTIONS`
  - Checks insecure cookie flags (`Secure`, `HttpOnly`, `SameSite`)
  - Detects server technology/version leakage headers
  - Checks HTTP to HTTPS redirect behavior
- System scan (Ubuntu-focused):
  - Detects overly permissive sensitive file permissions
  - Checks SSH root login configuration
  - Checks SSH password authentication setting
  - Checks UFW firewall status (if installed)
  - Optional world-writable file scan for selected directories
  - Checks unattended security-upgrade service status
- JSON output option for reporting
- Severity filtering and report file export (`--out`)
- CLI ASCII logo shown on tool run (and device-style ASCII cards in `network` / `lan-scan`)

## Legal Notice

Use this tool only on systems you own or have explicit permission to test.

## Project Structure

```text
.
├── main.py
├── requirements.txt
└── vscanner
    ├── __init__.py
    ├── checks.py
    ├── cli.py
    └── models.py
```

## Setup (Ubuntu)

```bash
cd /home/gaju/vuln
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Help

```bash
python3 main.py --help
```

### Network Scan

```bash
python3 main.py network --host 127.0.0.1 --ports 22,80,443,3306
```

```bash
python3 main.py network --host scanme.nmap.org --ports 1-1024 --workers 200 --timeout 0.4 --resolve --tls --min-severity LOW --out network_report.json --json
```

### LAN Scan (Wi-Fi Subnet)

```bash
python3 main.py lan-scan --ports 22,80,443,445 --discover-ports 22,80,443,445 --timeout 0.35 --workers 200 --host-limit 256 --out lan_report.txt
```

```bash
python3 main.py lan-scan --subnet 192.168.1.0/24 --os-detect --os-max-hosts 10 --json --out lan_report.json
```

Note: `--os-detect` uses `nmap -O`, which typically needs `sudo` for reliable results.

### Web Header Scan

```bash
python3 main.py web --url https://example.com
```

```bash
python3 main.py web --url http://example.com --check-methods --check-cookies --check-https-redirect --out web_report.txt
```

### System Scan (local Ubuntu machine)

```bash
python3 main.py system
```

```bash
python3 main.py system --world-writable --ww-paths /etc,/usr/local/bin --ww-limit 30 --min-severity LOW --out system_report.txt
```

### JSON Output

```bash
python3 main.py network --host 127.0.0.1 --json
```

## Example Output

```text
[HIGH] Open port detected: 22
  Details: Port 22 is reachable on 127.0.0.1.
  Recommendation: Close unused ports or restrict access using firewall rules.
```
