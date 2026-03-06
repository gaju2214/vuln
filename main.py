#!/usr/bin/env python3
import argparse

from vscanner.cli import run_lan_scan, run_network_scan, run_system_scan, run_web_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vscanner",
        description="Educational CLI vulnerability scanner for Ubuntu.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_net = sub.add_parser("network", help="Scan open ports on a target host.")
    p_net.add_argument("--host", required=True, help="Target host/IP (e.g., 127.0.0.1)")
    p_net.add_argument(
        "--ports",
        default="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080",
        help="Comma-separated ports and ranges (e.g., 22,80,443,8000-8100).",
    )
    p_net.add_argument("--tls", action="store_true", help="Also check TLS cert on port 443.")
    p_net.add_argument(
        "--timeout",
        type=float,
        default=0.6,
        help="Socket timeout in seconds (default: 0.6).",
    )
    p_net.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Parallel worker threads for port scanning (default: 100).",
    )
    p_net.add_argument(
        "--resolve",
        action="store_true",
        help="Resolve hostname to IP and include resolution findings.",
    )
    p_net.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH"],
        default="INFO",
        help="Only show findings at or above this severity.",
    )
    p_net.add_argument("--out", help="Write report output to file.")
    p_net.add_argument("--json", action="store_true", help="Output findings as JSON.")

    p_web = sub.add_parser("web", help="Check web security headers.")
    p_web.add_argument("--url", required=True, help="Target URL (e.g., https://example.com)")
    p_web.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds.")
    p_web.add_argument(
        "--check-methods",
        action="store_true",
        help="Check allowed HTTP methods via OPTIONS request.",
    )
    p_web.add_argument(
        "--check-cookies",
        action="store_true",
        help="Check cookie flags (Secure/HttpOnly/SameSite).",
    )
    p_web.add_argument(
        "--check-https-redirect",
        action="store_true",
        help="Check whether HTTP endpoint redirects to HTTPS.",
    )
    p_web.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH"],
        default="INFO",
        help="Only show findings at or above this severity.",
    )
    p_web.add_argument("--out", help="Write report output to file.")
    p_web.add_argument("--json", action="store_true", help="Output findings as JSON.")

    p_sys = sub.add_parser("system", help="Run local Ubuntu security checks.")
    p_sys.add_argument(
        "--world-writable",
        action="store_true",
        help="Scan selected paths for world-writable files.",
    )
    p_sys.add_argument(
        "--ww-paths",
        default="/etc,/usr/local/bin",
        help="Comma-separated directories to scan for world-writable files.",
    )
    p_sys.add_argument(
        "--ww-limit",
        type=int,
        default=25,
        help="Maximum world-writable findings to report.",
    )
    p_sys.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH"],
        default="INFO",
        help="Only show findings at or above this severity.",
    )
    p_sys.add_argument("--out", help="Write report output to file.")
    p_sys.add_argument("--json", action="store_true", help="Output findings as JSON.")

    p_lan = sub.add_parser("lan-scan", help="Scan hosts across local LAN/Wi-Fi subnet.")
    p_lan.add_argument(
        "--subnet",
        help="Target subnet in CIDR format (example: 192.168.1.0/24). If omitted, auto-detect is used.",
    )
    p_lan.add_argument(
        "--ports",
        default="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080",
        help="Ports to scan on each discovered host.",
    )
    p_lan.add_argument(
        "--discover-ports",
        default="22,53,80,139,443,445",
        help="Ports used only for live-host discovery phase.",
    )
    p_lan.add_argument("--timeout", type=float, default=0.35, help="Socket timeout in seconds.")
    p_lan.add_argument(
        "--workers",
        type=int,
        default=200,
        help="Parallel workers for host discovery (default: 200).",
    )
    p_lan.add_argument(
        "--host-limit",
        type=int,
        default=512,
        help="Maximum hosts to process from subnet (default: 512).",
    )
    p_lan.add_argument(
        "--no-reverse-dns",
        action="store_true",
        help="Disable reverse DNS lookups for discovered hosts.",
    )
    p_lan.add_argument(
        "--os-detect",
        action="store_true",
        help="Attempt OS fingerprinting for discovered hosts using nmap.",
    )
    p_lan.add_argument(
        "--os-max-hosts",
        type=int,
        default=16,
        help="Maximum hosts used for nmap OS fingerprinting.",
    )
    p_lan.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH"],
        default="INFO",
        help="Only show findings at or above this severity.",
    )
    p_lan.add_argument("--out", help="Write report output to file.")
    p_lan.add_argument("--json", action="store_true", help="Output findings as JSON.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "network":
        run_network_scan(
            args.host,
            args.ports,
            args.tls,
            args.json,
            args.timeout,
            args.workers,
            args.resolve,
            args.min_severity,
            args.out,
        )
    elif args.command == "web":
        run_web_scan(
            args.url,
            args.json,
            args.timeout,
            args.check_methods,
            args.check_cookies,
            args.check_https_redirect,
            args.min_severity,
            args.out,
        )
    elif args.command == "system":
        run_system_scan(
            args.json,
            args.world_writable,
            args.ww_paths,
            args.ww_limit,
            args.min_severity,
            args.out,
        )
    elif args.command == "lan-scan":
        run_lan_scan(
            args.subnet,
            args.ports,
            args.discover_ports,
            args.json,
            args.timeout,
            args.workers,
            args.host_limit,
            not args.no_reverse_dns,
            args.os_detect,
            args.os_max_hosts,
            args.min_severity,
            args.out,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
