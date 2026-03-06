#!/usr/bin/env python3
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from flask import Flask, render_template, request

BASE_DIR = Path(__file__).resolve().parent
MAIN_PY = BASE_DIR / "main.py"

app = Flask(__name__)

SCAN_TYPES = ["network", "web", "system", "lan-scan"]
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH"]
SUMMARY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]

DEFAULT_VALUES = {
    "scan_type": "network",
    "save_report_path": "",
    "network_host": "127.0.0.1",
    "network_ports": "22,80,443,445",
    "network_timeout": "0.6",
    "network_workers": "100",
    "network_min_severity": "INFO",
    "web_url": "https://example.com",
    "web_timeout": "4.0",
    "web_min_severity": "INFO",
    "system_ww_paths": "/etc,/usr/local/bin",
    "system_ww_limit": "25",
    "system_min_severity": "INFO",
    "lan_subnet": "",
    "lan_ports": "22,80,443,445",
    "lan_discover_ports": "22,80,443,445",
    "lan_timeout": "0.35",
    "lan_workers": "200",
    "lan_host_limit": "256",
    "lan_os_max_hosts": "16",
    "lan_min_severity": "INFO",
}

CHECKBOX_FIELDS = [
    "network_tls",
    "network_resolve",
    "web_check_methods",
    "web_check_cookies",
    "web_check_https_redirect",
    "system_world_writable",
    "lan_reverse_dns",
    "lan_os_detect",
]

TOOL_BANNER = r"""
__      __      _       _____
\ \    / /     | |     / ____|
 \ \  / /_   _ | |_ __| (___   ___ __ _ _ __  _ __   ___ _ __
  \ \/ /| | | || | '_ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \  / | |_| || | | | |___) | (_| (_| | | | | | | |  __/ |
    \/   \__,_||_|_| |_|____/ \___\__,_|_| |_|_| |_|\___|_|
""".strip("\n")


def _value(form, key: str, default: str = "") -> str:
    return (form.get(key, default) or "").strip()


def _bool(form, key: str, default: bool = False) -> bool:
    if key not in form:
        return default
    value = form.get(key, "")
    return value.lower() in {"on", "true", "1", "yes"}


def _add_option(cmd: List[str], flag: str, value: str) -> None:
    if value:
        cmd.extend([flag, value])


def build_scan_command(form) -> Tuple[List[str], str, int]:
    scan_type = _value(form, "scan_type", "network")
    if scan_type not in SCAN_TYPES:
        raise ValueError("Invalid scan type.")

    cmd: List[str] = [sys.executable, str(MAIN_PY), scan_type, "--json"]
    exec_timeout = 120

    report_path = _value(form, "save_report_path")
    _add_option(cmd, "--out", report_path)

    if scan_type == "network":
        host = _value(form, "network_host")
        if not host:
            raise ValueError("`Network Host` is required.")
        cmd.extend(["--host", host])
        _add_option(cmd, "--ports", _value(form, "network_ports"))
        _add_option(cmd, "--timeout", _value(form, "network_timeout", "0.6"))
        _add_option(cmd, "--workers", _value(form, "network_workers", "100"))
        if _bool(form, "network_tls"):
            cmd.append("--tls")
        if _bool(form, "network_resolve"):
            cmd.append("--resolve")
        _add_option(cmd, "--min-severity", _value(form, "network_min_severity", "INFO"))

    elif scan_type == "web":
        url = _value(form, "web_url")
        if not url:
            raise ValueError("`Web URL` is required.")
        cmd.extend(["--url", url])
        _add_option(cmd, "--timeout", _value(form, "web_timeout", "4.0"))
        if _bool(form, "web_check_methods"):
            cmd.append("--check-methods")
        if _bool(form, "web_check_cookies"):
            cmd.append("--check-cookies")
        if _bool(form, "web_check_https_redirect"):
            cmd.append("--check-https-redirect")
        _add_option(cmd, "--min-severity", _value(form, "web_min_severity", "INFO"))

    elif scan_type == "system":
        if _bool(form, "system_world_writable"):
            cmd.append("--world-writable")
        _add_option(cmd, "--ww-paths", _value(form, "system_ww_paths", "/etc,/usr/local/bin"))
        _add_option(cmd, "--ww-limit", _value(form, "system_ww_limit", "25"))
        _add_option(cmd, "--min-severity", _value(form, "system_min_severity", "INFO"))

    elif scan_type == "lan-scan":
        subnet = _value(form, "lan_subnet")
        _add_option(cmd, "--subnet", subnet)
        _add_option(cmd, "--ports", _value(form, "lan_ports"))
        _add_option(cmd, "--discover-ports", _value(form, "lan_discover_ports"))
        _add_option(cmd, "--timeout", _value(form, "lan_timeout", "0.35"))
        _add_option(cmd, "--workers", _value(form, "lan_workers", "200"))
        _add_option(cmd, "--host-limit", _value(form, "lan_host_limit", "256"))
        if not _bool(form, "lan_reverse_dns", default=True):
            cmd.append("--no-reverse-dns")
        if _bool(form, "lan_os_detect"):
            cmd.append("--os-detect")
        _add_option(cmd, "--os-max-hosts", _value(form, "lan_os_max_hosts", "16"))
        _add_option(cmd, "--min-severity", _value(form, "lan_min_severity", "INFO"))
        exec_timeout = 240

    return cmd, scan_type, exec_timeout


def parse_scanner_json(raw_output: str) -> Dict:
    raw_output = (raw_output or "").strip()
    if not raw_output:
        raise RuntimeError("Scanner returned empty output.")
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        snippet = raw_output[:400]
        raise RuntimeError(f"Scanner did not return valid JSON. Output: {snippet}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Scanner JSON format is invalid.")
    return data


def updated_form_values(post_form) -> Dict[str, str]:
    values = dict(DEFAULT_VALUES)
    values["lan_reverse_dns"] = "on"

    for key in DEFAULT_VALUES:
        if key in post_form:
            values[key] = _value(post_form, key, DEFAULT_VALUES[key])

    for key in CHECKBOX_FIELDS:
        values[key] = "on" if _bool(post_form, key) else ""
    return values


@app.route("/", methods=["GET", "POST"])
def index():
    values = dict(DEFAULT_VALUES)
    values["lan_reverse_dns"] = "on"
    result = None
    error = ""
    command_preview = ""

    if request.method == "POST":
        values = updated_form_values(request.form)
        try:
            cmd, scan_type, timeout = build_scan_command(request.form)
            command_preview = " ".join(shlex.quote(part) for part in cmd)
            proc = subprocess.run(
                cmd,
                cwd=BASE_DIR,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                message = (proc.stderr or proc.stdout or "").strip()
                if not message:
                    message = f"Scanner exited with code {proc.returncode}."
                raise RuntimeError(message)

            data = parse_scanner_json(proc.stdout)
            result = {
                "scan_type": scan_type,
                "generated_at_utc": data.get("generated_at_utc", ""),
                "summary": data.get("summary", {}),
                "findings": data.get("findings", []),
            }
        except subprocess.TimeoutExpired:
            error = "Scan timed out. Try reducing scan scope or increasing host/port specificity."
        except Exception as exc:
            error = str(exc)

    return render_template(
        "index.html",
        values=values,
        result=result,
        error=error,
        command_preview=command_preview,
        scan_types=SCAN_TYPES,
        severities=SEVERITIES,
        summary_order=SUMMARY_ORDER,
        tool_banner=TOOL_BANNER,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
