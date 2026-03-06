import concurrent.futures
import datetime as dt
import ipaddress
import os
import re
import socket
import ssl
import stat
import subprocess
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from vscanner.models import Finding


def parse_ports(ports_arg: str) -> List[int]:
    ports: List[int] = []
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            s, e = int(start), int(end)
            if s < 1 or e > 65535 or s > e:
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(s, e + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {part}")
            ports.append(p)
    return sorted(set(ports))


def resolve_target(host: str) -> Tuple[Optional[str], List[Finding]]:
    findings: List[Finding] = []
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        findings.append(
            Finding(
                severity="HIGH",
                title="Host resolution failed",
                details=f"Could not resolve '{host}': {exc}",
                recommendation="Verify DNS/host value and network connectivity.",
            )
        )
        return None, findings

    findings.append(
        Finding(
            severity="INFO",
            title="Host resolved",
            details=f"{host} resolved to {ip}.",
            recommendation="Use this IP in firewall allow/deny policy reviews.",
        )
    )
    try:
        if ipaddress.ip_address(ip).is_private:
            findings.append(
                Finding(
                    severity="INFO",
                    title="Private network target",
                    details=f"Target IP {ip} is in a private address range.",
                    recommendation="Ensure internal segmentation and ACL rules are enforced.",
                )
            )
    except ValueError:
        pass
    return ip, findings


def detect_local_subnet() -> Tuple[Optional[str], List[Finding]]:
    findings: List[Finding] = []
    default_iface: Optional[str] = None

    try:
        route_proc = subprocess.run(
            ["ip", "route", "show", "default"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except FileNotFoundError:
        findings.append(
            Finding(
                severity="HIGH",
                title="Subnet auto-detection failed",
                details="`ip` command not found on this system.",
                recommendation="Install `iproute2` or pass --subnet manually.",
            )
        )
        return None, findings
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Subnet auto-detection skipped",
                details=f"Could not inspect default route: {exc}",
                recommendation="Pass --subnet manually (example: 192.168.1.0/24).",
            )
        )
        return None, findings

    route_line = (route_proc.stdout or "").strip().splitlines()
    if route_line:
        match = re.search(r"\bdev\s+(\S+)", route_line[0])
        if match:
            default_iface = match.group(1)

    addr_cmd = ["ip", "-4", "-o", "addr", "show", "scope", "global"]
    if default_iface:
        addr_cmd = ["ip", "-4", "-o", "addr", "show", "dev", default_iface]

    try:
        addr_proc = subprocess.run(
            addr_cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Subnet auto-detection skipped",
                details=f"Could not inspect IPv4 addresses: {exc}",
                recommendation="Pass --subnet manually (example: 192.168.1.0/24).",
            )
        )
        return None, findings

    candidate = None
    for line in (addr_proc.stdout or "").splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", line)
        if match:
            candidate = match.group(1)
            break

    if not candidate:
        findings.append(
            Finding(
                severity="HIGH",
                title="Subnet auto-detection failed",
                details="No global IPv4 interface address was found.",
                recommendation="Pass --subnet manually (example: 192.168.1.0/24).",
            )
        )
        return None, findings

    network = str(ipaddress.ip_interface(candidate).network)
    iface_text = default_iface if default_iface else "auto-selected interface"
    findings.append(
        Finding(
            severity="INFO",
            title="Detected local subnet",
            details=f"Interface {iface_text} with address {candidate} mapped to subnet {network}.",
            recommendation="Scan only networks you own or are authorized to test.",
        )
    )
    return network, findings


def _host_has_any_open_port(host: str, ports: List[int], timeout: float) -> bool:
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def discover_live_hosts(
    subnet: str,
    probe_ports: List[int],
    timeout: float = 0.35,
    workers: int = 200,
    host_limit: int = 512,
) -> Tuple[List[str], List[Finding]]:
    findings: List[Finding] = []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        findings.append(
            Finding(
                severity="HIGH",
                title="Invalid subnet format",
                details=f"Could not parse subnet '{subnet}': {exc}",
                recommendation="Use CIDR format (example: 192.168.1.0/24).",
            )
        )
        return [], findings

    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > host_limit:
        findings.append(
            Finding(
                severity="INFO",
                title="LAN scan host list truncated",
                details=f"Subnet has {len(hosts)} hosts; scanning first {host_limit}.",
                recommendation="Increase --host-limit or use a smaller subnet.",
            )
        )
        hosts = hosts[:host_limit]

    if not probe_ports:
        probe_ports = [22, 80, 443, 445, 139, 53]

    if not hosts:
        return [], findings

    max_workers = min(max(workers, 1), len(hosts))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                lambda host: (host, _host_has_any_open_port(host, probe_ports, timeout)),
                hosts,
            )
        )

    live_hosts = sorted([host for host, alive in results if alive], key=lambda x: tuple(int(n) for n in x.split(".")))
    findings.append(
        Finding(
            severity="INFO",
            title="LAN discovery completed",
            details=f"Discovered {len(live_hosts)} live host(s) in {network.with_prefixlen}.",
            recommendation="Run targeted scans on critical assets first.",
        )
    )
    return live_hosts, findings


def reverse_dns_name(host: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(host)
        return name
    except Exception:
        return None


def check_os_with_nmap(hosts: List[str], max_hosts: int = 16, timeout: int = 45) -> List[Finding]:
    findings: List[Finding] = []
    if not hosts:
        return findings

    targets = hosts[:max_hosts]
    if len(hosts) > max_hosts:
        findings.append(
            Finding(
                severity="INFO",
                title="OS detection host list truncated",
                details=f"OS fingerprinting limited to first {max_hosts} hosts for runtime control.",
                recommendation="Increase --os-max-hosts if you need broader OS guessing.",
            )
        )

    try:
        proc = subprocess.run(
            ["nmap", "-O", "-Pn", "-T4", *targets],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        findings.append(
            Finding(
                severity="INFO",
                title="OS detection skipped",
                details="`nmap` is not installed.",
                recommendation="Install nmap (`sudo apt install nmap`) and retry with --os-detect.",
            )
        )
        return findings
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="OS detection skipped",
                details=f"Could not execute nmap OS detection: {exc}",
                recommendation="Run manually with sufficient permissions if needed.",
            )
        )
        return findings

    combined = (proc.stdout + "\n" + proc.stderr).lower()
    if "requires root privileges" in combined or "you requested a scan type which requires root privileges" in combined:
        findings.append(
            Finding(
                severity="INFO",
                title="OS detection requires elevated privileges",
                details="nmap -O needs root privileges on most systems for reliable fingerprinting.",
                recommendation="Run the scan with sudo on authorized environments.",
            )
        )
        return findings

    current_host: Optional[str] = None
    guessed = 0
    for line in proc.stdout.splitlines():
        report_match = re.match(r"^Nmap scan report for (.+)$", line.strip())
        if report_match:
            current_host = report_match.group(1)
            continue
        if not current_host:
            continue

        guess = None
        if line.startswith("OS details:"):
            guess = line.split(":", 1)[1].strip()
        elif line.startswith("Running:"):
            guess = line.split(":", 1)[1].strip()
        elif line.startswith("Aggressive OS guesses:"):
            guess = line.split(":", 1)[1].strip()

        if guess:
            guessed += 1
            findings.append(
                Finding(
                    severity="INFO",
                    title=f"OS guess for {current_host}",
                    details=guess,
                    recommendation="Treat OS fingerprinting as probabilistic; verify manually for accuracy.",
                )
            )

    if guessed == 0:
        findings.append(
            Finding(
                severity="INFO",
                title="OS detection inconclusive",
                details="nmap completed but no strong OS fingerprints were identified.",
                recommendation="Try scanning with sudo and ensure hosts are reachable.",
            )
        )
    return findings


def probe_port(host: str, port: int, timeout: float) -> Optional[Tuple[int, Optional[str]]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            return (port, grab_banner(host, port, timeout=timeout))
    except OSError:
        return None
    finally:
        sock.close()
    return None


def scan_open_ports(
    host: str,
    ports: List[int],
    timeout: float = 0.6,
    workers: int = 100,
) -> List[Tuple[int, Optional[str]]]:
    if not ports:
        return []

    if workers <= 1:
        out = [probe_port(host, port, timeout) for port in ports]
    else:
        max_workers = min(max(workers, 1), len(ports))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            out = list(executor.map(lambda p: probe_port(host, p, timeout), ports))

    open_ports = [item for item in out if item is not None]
    return sorted(open_ports, key=lambda x: x[0])


def grab_banner(host: str, port: int, timeout: float = 0.8) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        try:
            sock.sendall(b"\r\n")
        except OSError:
            pass
        data = sock.recv(128)
        if data:
            return data.decode(errors="ignore").strip()
    except OSError:
        return None
    finally:
        sock.close()
    return None


def evaluate_open_ports(host: str, open_ports: List[Tuple[int, Optional[str]]]) -> List[Finding]:
    findings: List[Finding] = []
    high_risk_ports = {21, 23, 25, 110, 143, 3306, 5432, 6379, 27017}
    medium_risk_ports = {22, 80, 139, 445, 3389}

    for port, banner in open_ports:
        if port in high_risk_ports:
            sev = "HIGH"
        elif port in medium_risk_ports:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        extra = f" Banner: {banner}" if banner else ""
        findings.append(
            Finding(
                severity=sev,
                title=f"Open port detected: {port}",
                details=f"Port {port} is reachable on {host}.{extra}",
                recommendation="Close unused ports or restrict access using firewall rules.",
            )
        )
    return findings


def evaluate_exposed_service_risks(open_ports: List[Tuple[int, Optional[str]]]) -> List[Finding]:
    findings: List[Finding] = []
    risky_ports = {
        21: ("HIGH", "FTP exposed", "Use SFTP/FTPS and restrict network exposure."),
        23: ("HIGH", "Telnet exposed", "Disable Telnet and use SSH with key auth."),
        25: ("MEDIUM", "SMTP exposed", "Restrict relay/network access and harden SMTP config."),
        3306: ("HIGH", "MySQL exposed", "Bind DB to private interface or enforce strict ACL/TLS."),
        5432: ("HIGH", "PostgreSQL exposed", "Restrict access via pg_hba.conf and network firewall."),
        6379: ("HIGH", "Redis exposed", "Disable public exposure and enforce auth/TLS."),
        27017: ("HIGH", "MongoDB exposed", "Disable public exposure and enable auth."),
    }
    for port, _ in open_ports:
        if port in risky_ports:
            sev, title, rec = risky_ports[port]
            findings.append(
                Finding(
                    severity=sev,
                    title=title,
                    details=f"Port {port} is open and commonly abused when publicly reachable.",
                    recommendation=rec,
                )
            )
    return findings


def evaluate_banner_risks(open_ports: List[Tuple[int, Optional[str]]]) -> List[Finding]:
    findings: List[Finding] = []
    signatures = [
        (r"vsftpd\s*2\.3\.4", "HIGH", "Backdoored VSFTPD signature seen"),
        (r"openssh[_/\s](5|6)\.", "MEDIUM", "Legacy OpenSSH version banner"),
        (r"apache/?2\.2", "MEDIUM", "Legacy Apache 2.2 banner"),
        (r"microsoft-iis/6\.0", "HIGH", "Outdated IIS 6.0 banner"),
    ]
    for port, banner in open_ports:
        if not banner:
            continue
        lower_banner = banner.lower()
        for pattern, sev, title in signatures:
            if re.search(pattern, lower_banner):
                findings.append(
                    Finding(
                        severity=sev,
                        title=title,
                        details=f"Service banner on port {port}: {banner}",
                        recommendation="Update service version and verify against current security advisories.",
                    )
                )

        if "/" in banner and re.search(r"\d+\.\d+", banner):
            findings.append(
                Finding(
                    severity="LOW",
                    title="Service version disclosure in banner",
                    details=f"Port {port} reveals version-like banner data: {banner}",
                    recommendation="Minimize service version disclosure where possible.",
                )
            )
    return findings


def get_tls_expiry(host: str, port: int = 443, timeout: float = 2.0) -> Optional[dt.datetime]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            not_after = cert.get("notAfter")
            if not not_after:
                return None
            return dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")


def check_tls_certificate(host: str, port: int = 443) -> List[Finding]:
    findings: List[Finding] = []
    try:
        expiry = get_tls_expiry(host, port)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="TLS certificate check skipped",
                details=f"Unable to read certificate from {host}:{port}: {exc}",
                recommendation="Ensure the host supports TLS and is reachable.",
            )
        )
        return findings

    if expiry is None:
        findings.append(
            Finding(
                severity="INFO",
                title="TLS certificate not found",
                details=f"No TLS certificate metadata was returned by {host}:{port}.",
                recommendation="Verify HTTPS/TLS is configured correctly.",
            )
        )
        return findings

    now = dt.datetime.utcnow()
    days_left = (expiry - now).days
    if days_left < 0:
        findings.append(
            Finding(
                severity="HIGH",
                title="TLS certificate expired",
                details=f"Certificate for {host}:{port} expired on {expiry.isoformat()} UTC.",
                recommendation="Renew and deploy a valid TLS certificate immediately.",
            )
        )
    elif days_left <= 30:
        findings.append(
            Finding(
                severity="MEDIUM",
                title="TLS certificate expiring soon",
                details=f"Certificate for {host}:{port} will expire in {days_left} days.",
                recommendation="Schedule certificate renewal before expiry.",
            )
        )
    return findings


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"http://{url}"
    return url


def fetch_response(url: str, method: str, timeout: float):
    target = normalize_url(url)
    req = Request(target, method=method, headers={"User-Agent": "vscanner/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        headers = resp.headers
        set_cookies = headers.get_all("Set-Cookie", [])
    return target, final_url, headers, set_cookies


def check_http_headers(url: str, timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    required_headers: Dict[str, str] = {
        "Content-Security-Policy": "Define a strict CSP to reduce XSS risk.",
        "X-Content-Type-Options": "Set to 'nosniff' to prevent MIME sniffing.",
        "X-Frame-Options": "Set to DENY or SAMEORIGIN to reduce clickjacking.",
        "Strict-Transport-Security": "Enable HSTS for HTTPS-only transport.",
        "Referrer-Policy": "Set a restrictive referrer policy.",
    }

    try:
        _, final_url, headers, _ = fetch_response(url, "GET", timeout)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Web header scan failed",
                details=f"Could not scan {normalize_url(url)}: {exc}",
                recommendation="Verify URL, network connectivity, and server availability.",
            )
        )
        return findings

    for header, rec in required_headers.items():
        if headers.get(header) is None:
            sev = "MEDIUM" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "LOW"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Missing HTTP security header: {header}",
                    details=f"{header} is not present in the response from {final_url}.",
                    recommendation=rec,
                )
            )
    return findings


def check_http_methods(url: str, timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    try:
        _, final_url, headers, _ = fetch_response(url, "OPTIONS", timeout)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="HTTP methods check skipped",
                details=f"Could not issue OPTIONS request: {exc}",
                recommendation="Verify the endpoint is reachable and allows OPTIONS checks.",
            )
        )
        return findings

    allow_header = headers.get("Allow", "")
    methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    dangerous = sorted(methods.intersection({"PUT", "DELETE", "TRACE", "CONNECT"}))
    if dangerous:
        findings.append(
            Finding(
                severity="MEDIUM",
                title="Potentially dangerous HTTP methods allowed",
                details=f"{final_url} allows: {', '.join(dangerous)}",
                recommendation="Disable unnecessary methods at server/reverse-proxy level.",
            )
        )
    return findings


def check_cookie_security(url: str, timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    try:
        _, final_url, _, set_cookies = fetch_response(url, "GET", timeout)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Cookie check skipped",
                details=f"Could not fetch response cookies: {exc}",
                recommendation="Re-run when target is reachable.",
            )
        )
        return findings

    for cookie in set_cookies:
        base = cookie.split(";", 1)[0].strip() or "<unknown>"
        attrs = {part.strip().lower() for part in cookie.split(";")[1:]}
        missing: List[str] = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(attr.startswith("samesite=") for attr in attrs):
            missing.append("SameSite")
        if missing:
            sev = "MEDIUM" if {"Secure", "HttpOnly"}.intersection(missing) else "LOW"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Insecure cookie flags: {base}",
                    details=f"Cookie from {final_url} is missing {', '.join(missing)}.",
                    recommendation="Set Secure, HttpOnly, and SameSite for session-sensitive cookies.",
                )
            )
    return findings


def check_server_header_exposure(url: str, timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    try:
        _, final_url, headers, _ = fetch_response(url, "GET", timeout)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Server banner check skipped",
                details=f"Could not inspect response headers: {exc}",
                recommendation="Re-run when target is reachable.",
            )
        )
        return findings

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            Finding(
                severity="LOW",
                title="Server version disclosure",
                details=f"{final_url} leaks server header detail: {server}",
                recommendation="Reduce server banner detail in production responses.",
            )
        )
    if powered_by:
        findings.append(
            Finding(
                severity="LOW",
                title="X-Powered-By header exposed",
                details=f"{final_url} returns X-Powered-By: {powered_by}",
                recommendation="Disable X-Powered-By to reduce technology fingerprinting.",
            )
        )
    return findings


def check_https_redirect(url: str, timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    target = normalize_url(url)
    parsed = urlparse(target)
    if parsed.scheme != "http":
        return findings

    try:
        _, final_url, _, _ = fetch_response(target, "GET", timeout)
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="HTTPS redirect check skipped",
                details=f"Could not verify redirect behavior: {exc}",
                recommendation="Re-run when target is reachable.",
            )
        )
        return findings

    if not final_url.startswith("https://"):
        findings.append(
            Finding(
                severity="MEDIUM",
                title="HTTP endpoint does not enforce HTTPS redirect",
                details=f"Request to {target} did not end on HTTPS URL (final: {final_url}).",
                recommendation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
            )
        )
    return findings


def check_sensitive_file_permissions() -> List[Finding]:
    findings: List[Finding] = []
    targets = [
        ("/etc/passwd", 0o644),
        ("/etc/shadow", 0o640),
        ("/etc/ssh/sshd_config", 0o600),
    ]
    for path, expected_max in targets:
        if not os.path.exists(path):
            continue
        try:
            st_mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError as exc:
            findings.append(
                Finding(
                    severity="INFO",
                    title="Permission check skipped",
                    details=f"Could not stat {path}: {exc}",
                    recommendation="Run scan with sufficient permissions if needed.",
                )
            )
            continue

        if st_mode > expected_max:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    title=f"Overly permissive file mode: {path}",
                    details=f"Detected mode {oct(st_mode)}; expected <= {oct(expected_max)}.",
                    recommendation=f"Restrict permissions, e.g. `chmod {oct(expected_max)[2:]} {path}`.",
                )
            )
    return findings


def _read_sshd_config() -> Tuple[Optional[str], List[Finding]]:
    findings: List[Finding] = []
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        return None, findings
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(), findings
    except OSError as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="SSH config check skipped",
                details=f"Could not read {path}: {exc}",
                recommendation="Ensure scanner has read access if this check is required.",
            )
        )
        return None, findings


def check_ssh_root_login() -> List[Finding]:
    findings: List[Finding] = []
    data, io_findings = _read_sshd_config()
    findings.extend(io_findings)
    if not data:
        return findings

    match = re.search(r"^\s*PermitRootLogin\s+(\S+)", data, flags=re.MULTILINE)
    if match and match.group(1).lower() in {"yes", "without-password", "prohibit-password"}:
        findings.append(
            Finding(
                severity="MEDIUM",
                title="SSH root login potentially enabled",
                details=f"`PermitRootLogin {match.group(1)}` detected in /etc/ssh/sshd_config.",
                recommendation="Set `PermitRootLogin no` and restart SSH service.",
            )
        )
    return findings


def check_ssh_password_auth() -> List[Finding]:
    findings: List[Finding] = []
    data, io_findings = _read_sshd_config()
    findings.extend(io_findings)
    if not data:
        return findings

    match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", data, flags=re.MULTILINE)
    if match and match.group(1).lower() == "yes":
        findings.append(
            Finding(
                severity="MEDIUM",
                title="SSH password authentication enabled",
                details="`PasswordAuthentication yes` detected in /etc/ssh/sshd_config.",
                recommendation="Disable password auth and use key-based authentication.",
            )
        )
    return findings


def check_world_writable_files(paths: List[str], max_findings: int = 25) -> List[Finding]:
    findings: List[Finding] = []
    if max_findings <= 0:
        return findings

    count = 0
    for base in paths:
        if not os.path.exists(base):
            continue

        for root, _, files in os.walk(base):
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & stat.S_IWOTH:
                    sev = "MEDIUM" if (st.st_mode & stat.S_IXUSR) else "LOW"
                    findings.append(
                        Finding(
                            severity=sev,
                            title="World-writable file detected",
                            details=f"{full} has mode {oct(stat.S_IMODE(st.st_mode))}.",
                            recommendation="Remove world-writable bit unless explicitly required.",
                        )
                    )
                    count += 1
                    if count >= max_findings:
                        findings.append(
                            Finding(
                                severity="INFO",
                                title="World-writable scan truncated",
                                details=f"Reached max findings limit ({max_findings}).",
                                recommendation="Increase scan limit for deeper analysis if needed.",
                            )
                        )
                        return findings
    return findings


def check_unattended_upgrades() -> List[Finding]:
    findings: List[Finding] = []
    try:
        proc = subprocess.run(
            ["systemctl", "is-enabled", "unattended-upgrades"],
            check=False,
            capture_output=True,
            text=True,
            timeout=4,
        )
    except FileNotFoundError:
        return findings
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="Auto-update check skipped",
                details=f"Could not verify unattended-upgrades service: {exc}",
                recommendation="Check manually via systemctl if available.",
            )
        )
        return findings

    status = (proc.stdout or proc.stderr).strip().lower()
    if "failed to connect to bus" in status or "operation not permitted" in status:
        findings.append(
            Finding(
                severity="INFO",
                title="Auto-update check skipped",
                details=f"systemctl access unavailable: {status}",
                recommendation="Run this check on a full Ubuntu host session with systemd access.",
            )
        )
        return findings

    if status and "enabled" not in status:
        findings.append(
            Finding(
                severity="LOW",
                title="Unattended security upgrades not enabled",
                details=f"systemctl returned: {status}",
                recommendation="Enable automatic security updates where policy allows.",
            )
        )
    return findings


def check_ufw_status() -> List[Finding]:
    findings: List[Finding] = []
    try:
        proc = subprocess.run(
            ["ufw", "status"],
            check=False,
            capture_output=True,
            text=True,
            timeout=4,
        )
    except FileNotFoundError:
        findings.append(
            Finding(
                severity="INFO",
                title="UFW not installed",
                details="`ufw` command not found.",
                recommendation="Install/configure UFW or use another host firewall.",
            )
        )
        return findings
    except Exception as exc:
        findings.append(
            Finding(
                severity="INFO",
                title="UFW check skipped",
                details=f"Could not execute `ufw status`: {exc}",
                recommendation="Run manually: `sudo ufw status`.",
            )
        )
        return findings

    output = (proc.stdout + "\n" + proc.stderr).strip().lower()
    if "inactive" in output:
        findings.append(
            Finding(
                severity="MEDIUM",
                title="Firewall appears inactive",
                details="UFW status returned inactive.",
                recommendation="Enable firewall rules: `sudo ufw enable` (after policy review).",
            )
        )
    return findings


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts
