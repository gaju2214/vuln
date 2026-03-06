import datetime as dt
import json
from typing import List, Optional

from vscanner.checks import (
    check_cookie_security,
    check_http_headers,
    check_http_methods,
    check_https_redirect,
    check_os_with_nmap,
    check_sensitive_file_permissions,
    check_server_header_exposure,
    check_ssh_password_auth,
    check_ssh_root_login,
    check_tls_certificate,
    check_ufw_status,
    check_unattended_upgrades,
    check_world_writable_files,
    detect_local_subnet,
    discover_live_hosts,
    evaluate_banner_risks,
    evaluate_exposed_service_risks,
    evaluate_open_ports,
    parse_ports,
    reverse_dns_name,
    resolve_target,
    scan_open_ports,
    summarize,
)
from vscanner.models import Finding

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

TOOL_BANNER = r"""
__      __      _       _____
\ \    / /     | |     / ____|
 \ \  / /_   _ | |_ __| (___   ___ __ _ _ __  _ __   ___ _ __
  \ \/ /| | | || | '_ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \  / | |_| || | | | |___) | (_| (_| | | | | | | |  __/ |
    \/   \__,_||_|_| |_|____/ \___\__,_|_| |_|_| |_|\___|_|
"""

DEVICE_ART = {
    "router": [
        "+----------------+",
        "|     ROUTER     |",
        "|   [==][==]     |",
        "+----------------+",
    ],
    "server": [
        "+----------------+",
        "|     SERVER     |",
        "|   [::::::]     |",
        "+----------------+",
    ],
    "workstation": [
        "+----------------+",
        "|   WORKSTATION  |",
        "|    __[]__      |",
        "+----------------+",
    ],
    "printer": [
        "+----------------+",
        "|    PRINTER     |",
        "|   [_____]      |",
        "+----------------+",
    ],
    "camera": [
        "+----------------+",
        "|   IP CAMERA    |",
        "|     (o)        |",
        "+----------------+",
    ],
    "unknown": [
        "+----------------+",
        "|    DEVICE      |",
        "|    [????]      |",
        "+----------------+",
    ],
}


def classify_device_from_ports(open_ports: List[int]) -> str:
    port_set = set(open_ports)
    if 9100 in port_set:
        return "printer"
    if 554 in port_set or 8554 in port_set:
        return "camera"
    if ({53, 67, 68} & port_set) and ({80, 443} & port_set):
        return "router"
    if {3306, 5432, 6379, 27017} & port_set:
        return "server"
    if {22, 80, 443} & port_set and len(port_set) >= 2:
        return "server"
    if {139, 445, 3389} & port_set:
        return "workstation"
    if port_set:
        return "workstation"
    return "unknown"


def render_device_logo(host: str, open_ports: List[int], dns_name: Optional[str] = None) -> str:
    device_type = classify_device_from_ports(open_ports)
    art = DEVICE_ART.get(device_type, DEVICE_ART["unknown"])
    name_text = f"{host} ({dns_name})" if dns_name else host
    ports_text = ", ".join(str(p) for p in open_ports) if open_ports else "none"

    lines: List[str] = []
    lines.extend(art)
    lines.append(f"Host: {name_text}")
    lines.append(f"Type Guess: {device_type}")
    lines.append(f"Open Ports: {ports_text}")
    return "\n".join(lines)


def format_findings_text(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."

    lines: List[str] = []
    for item in findings:
        lines.append(f"[{item.severity}] {item.title}")
        lines.append(f"  Details: {item.details}")
        lines.append(f"  Recommendation: {item.recommendation}")
    counts = summarize(findings)
    lines.append("")
    lines.append("Summary:")
    lines.append(
        f"  HIGH={counts.get('HIGH', 0)}  "
        f"MEDIUM={counts.get('MEDIUM', 0)}  "
        f"LOW={counts.get('LOW', 0)}  "
        f"INFO={counts.get('INFO', 0)}"
    )
    return "\n".join(lines)


def filter_findings(findings: List[Finding], min_severity: str) -> List[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]


def output(findings: List[Finding], as_json: bool, out_file: Optional[str], prelude: Optional[str] = None) -> None:
    if as_json:
        payload = {
            "generated_at_utc": dt.datetime.utcnow().isoformat() + "Z",
            "findings": [f.to_dict() for f in findings],
            "summary": summarize(findings),
        }
        rendered = json.dumps(payload, indent=2)
    else:
        body = format_findings_text(findings)
        if prelude:
            rendered = prelude.rstrip() + "\n\n" + body
        else:
            rendered = body

    print(rendered)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(rendered)
            fh.write("\n")


def run_network_scan(
    host: str,
    ports_raw: str,
    tls: bool,
    as_json: bool,
    timeout: float,
    workers: int,
    resolve: bool,
    min_severity: str,
    out_file: Optional[str],
) -> None:
    try:
        ports = parse_ports(ports_raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid --ports value: {exc}") from exc

    target = host
    findings: List[Finding] = []
    if resolve:
        resolved, resolve_findings = resolve_target(host)
        findings.extend(resolve_findings)
        if resolved is None:
            output(filter_findings(findings, min_severity), as_json, out_file)
            return
        target = resolved

    open_ports = scan_open_ports(target, ports, timeout=timeout, workers=workers)
    findings.extend(evaluate_open_ports(target, open_ports))
    findings.extend(evaluate_exposed_service_risks(open_ports))
    findings.extend(evaluate_banner_risks(open_ports))

    if tls:
        findings.extend(check_tls_certificate(host, 443))

    prelude = None
    if not as_json:
        open_port_numbers = [port for port, _ in open_ports]
        device_logo = render_device_logo(host=target, open_ports=open_port_numbers)
        prelude = TOOL_BANNER.strip("\n") + "\n\n" + device_logo

    output(filter_findings(findings, min_severity), as_json, out_file, prelude=prelude)


def run_lan_scan(
    subnet: Optional[str],
    ports_raw: str,
    discover_ports_raw: str,
    as_json: bool,
    timeout: float,
    workers: int,
    host_limit: int,
    reverse_dns: bool,
    os_detect: bool,
    os_max_hosts: int,
    min_severity: str,
    out_file: Optional[str],
) -> None:
    try:
        target_ports = parse_ports(ports_raw)
        discover_ports = parse_ports(discover_ports_raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid port configuration: {exc}") from exc

    findings: List[Finding] = []
    logos: List[str] = []
    effective_subnet = subnet
    if not effective_subnet:
        detected_subnet, detect_findings = detect_local_subnet()
        findings.extend(detect_findings)
        if not detected_subnet:
            output(filter_findings(findings, min_severity), as_json, out_file)
            return
        effective_subnet = detected_subnet
    else:
        findings.append(
            Finding(
                severity="INFO",
                title="Using provided subnet",
                details=f"LAN scan subnet set to {effective_subnet}.",
                recommendation="Ensure this subnet is in your authorized test scope.",
            )
        )

    live_hosts, discovery_findings = discover_live_hosts(
        effective_subnet,
        probe_ports=discover_ports,
        timeout=timeout,
        workers=workers,
        host_limit=host_limit,
    )
    findings.extend(discovery_findings)

    for host in live_hosts:
        dns_name = reverse_dns_name(host) if reverse_dns else None
        host_label = f"{host} ({dns_name})" if dns_name else host
        findings.append(
            Finding(
                severity="INFO",
                title=f"Live host: {host}",
                details=f"Target discovered: {host_label}",
                recommendation="Review exposed services for this host.",
            )
        )

        open_ports = scan_open_ports(host, target_ports, timeout=timeout, workers=min(64, len(target_ports)))
        open_port_numbers = [port for port, _ in open_ports]
        if not as_json:
            logos.append(render_device_logo(host=host, open_ports=open_port_numbers, dns_name=dns_name))
        findings.extend(evaluate_open_ports(host, open_ports))

        for item in evaluate_exposed_service_risks(open_ports):
            item.title = f"{item.title} ({host})"
            item.details = f"Host {host}: {item.details}"
            findings.append(item)

        for item in evaluate_banner_risks(open_ports):
            item.title = f"{item.title} ({host})"
            item.details = f"Host {host}: {item.details}"
            findings.append(item)

    if os_detect:
        findings.extend(check_os_with_nmap(live_hosts, max_hosts=os_max_hosts))

    prelude = None
    if not as_json:
        prelude_parts = [TOOL_BANNER.strip("\n")]
        if logos:
            prelude_parts.append("\n\n".join(logos))
        prelude = "\n\n".join(prelude_parts)

    output(filter_findings(findings, min_severity), as_json, out_file, prelude=prelude)


def run_web_scan(
    url: str,
    as_json: bool,
    timeout: float,
    methods: bool,
    cookies: bool,
    https_redirect: bool,
    min_severity: str,
    out_file: Optional[str],
) -> None:
    findings: List[Finding] = []
    findings.extend(check_http_headers(url, timeout=timeout))
    findings.extend(check_server_header_exposure(url, timeout=timeout))
    if methods:
        findings.extend(check_http_methods(url, timeout=timeout))
    if cookies:
        findings.extend(check_cookie_security(url, timeout=timeout))
    if https_redirect:
        findings.extend(check_https_redirect(url, timeout=timeout))
    prelude = TOOL_BANNER.strip("\n") if not as_json else None
    output(filter_findings(findings, min_severity), as_json, out_file, prelude=prelude)


def run_system_scan(
    as_json: bool,
    world_writable: bool,
    ww_paths: str,
    ww_limit: int,
    min_severity: str,
    out_file: Optional[str],
) -> None:
    findings: List[Finding] = []
    findings.extend(check_sensitive_file_permissions())
    findings.extend(check_ssh_root_login())
    findings.extend(check_ssh_password_auth())
    findings.extend(check_unattended_upgrades())
    findings.extend(check_ufw_status())

    if world_writable:
        scan_paths = [p.strip() for p in ww_paths.split(",") if p.strip()]
        if scan_paths:
            findings.extend(check_world_writable_files(scan_paths, max_findings=ww_limit))

    prelude = TOOL_BANNER.strip("\n") if not as_json else None
    output(filter_findings(findings, min_severity), as_json, out_file, prelude=prelude)
