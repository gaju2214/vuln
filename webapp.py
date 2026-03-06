#!/usr/bin/env python3
import csv
import io
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Flask, Response, abort, render_template, request

BASE_DIR = Path(__file__).resolve().parent
MAIN_PY = BASE_DIR / "main.py"

app = Flask(__name__)

SCAN_TYPES = ["network", "web", "system", "lan-scan"]
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH"]
SUMMARY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]
EXPORT_CACHE: Dict[str, Dict] = {}
EXPORT_TTL_SECONDS = 1800
EXPORT_MAX_ITEMS = 128

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


def prune_export_cache() -> None:
    now = time.time()
    expired = [key for key, item in EXPORT_CACHE.items() if (now - item.get("created_at", now)) > EXPORT_TTL_SECONDS]
    for key in expired:
        EXPORT_CACHE.pop(key, None)

    if len(EXPORT_CACHE) <= EXPORT_MAX_ITEMS:
        return

    sorted_items = sorted(EXPORT_CACHE.items(), key=lambda kv: kv[1].get("created_at", 0))
    for key, _ in sorted_items[: len(EXPORT_CACHE) - EXPORT_MAX_ITEMS]:
        EXPORT_CACHE.pop(key, None)


def store_export_result(result: Dict) -> str:
    prune_export_cache()
    export_id = uuid.uuid4().hex
    EXPORT_CACHE[export_id] = {
        "created_at": time.time(),
        "result": result,
    }
    return export_id


def get_export_result(export_id: str) -> Optional[Dict]:
    prune_export_cache()
    item = EXPORT_CACHE.get(export_id)
    if not item:
        return None
    return item.get("result")


def safe_filename_fragment(value: str, fallback: str = "report") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", value or "").strip("_")
    return cleaned or fallback


def build_csv_report(result: Dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out)

    writer.writerow(["scan_type", result.get("scan_type", "")])
    writer.writerow(["generated_at_utc", result.get("generated_at_utc", "")])
    writer.writerow([])

    writer.writerow(["summary_severity", "count"])
    summary = result.get("summary", {}) or {}
    for key in SUMMARY_ORDER:
        writer.writerow([key, summary.get(key, 0)])
    writer.writerow([])

    writer.writerow(["severity", "title", "details", "recommendation"])
    for item in result.get("findings", []) or []:
        writer.writerow(
            [
                item.get("severity", ""),
                item.get("title", ""),
                item.get("details", ""),
                item.get("recommendation", ""),
            ]
        )
    return out.getvalue()


def _wrap_text(text: str, width: int = 95) -> List[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines: List[str] = []
    current = words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf_report(result: Dict) -> bytes:
    scan_type = result.get("scan_type", "scan")
    generated_at = result.get("generated_at_utc", "")
    summary = result.get("summary", {}) or {}
    findings = result.get("findings", []) or []

    lines: List[str] = []
    lines.append("VulnScanner Report")
    lines.append(f"Scan Type: {scan_type}")
    lines.append(f"Generated: {generated_at}")
    lines.append("")
    lines.append("Summary")
    for key in SUMMARY_ORDER:
        lines.append(f"{key}: {summary.get(key, 0)}")
    lines.append("")
    lines.append("Findings")

    if not findings:
        lines.append("No findings.")
    else:
        for idx, item in enumerate(findings, start=1):
            lines.append(f"{idx}. [{item.get('severity', '')}] {item.get('title', '')}")
            lines.extend(_wrap_text(f"Details: {item.get('details', '')}"))
            lines.extend(_wrap_text(f"Recommendation: {item.get('recommendation', '')}"))
            lines.append("")

    lines_per_page = 48
    pages: List[List[str]] = []
    for i in range(0, len(lines), lines_per_page):
        pages.append(lines[i : i + lines_per_page])
    if not pages:
        pages = [["VulnScanner Report", "No content."]]

    objects: List[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1

    kids_refs = []
    for page_index in range(len(pages)):
        page_obj_num = 4 + page_index * 2
        kids_refs.append(f"{page_obj_num} 0 R")
    pages_obj = f"<< /Type /Pages /Kids [{' '.join(kids_refs)}] /Count {len(pages)} >>".encode("latin-1")
    objects.append(pages_obj)  # 2
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # 3

    for page_index, page_lines in enumerate(pages):
        content_lines = [b"BT", b"/F1 10 Tf", b"50 800 Td", b"14 TL"]
        first = True
        for line in page_lines:
            escaped = _escape_pdf_text(line).encode("latin-1", errors="replace")
            if first:
                content_lines.append(b"(" + escaped + b") Tj")
                first = False
            else:
                content_lines.append(b"T*")
                content_lines.append(b"(" + escaped + b") Tj")
        content_lines.append(b"ET")
        content_stream = b"\n".join(content_lines)
        content_obj = b"<< /Length " + str(len(content_stream)).encode("ascii") + b" >>\nstream\n" + content_stream + b"\nendstream"

        page_obj_num = 4 + page_index * 2
        content_obj_num = page_obj_num + 1
        page_obj = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_num} 0 R >>"
        ).encode("latin-1")

        objects.append(page_obj)
        objects.append(content_obj)

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]

    for idx, obj in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{idx} 0 obj\n".encode("ascii"))
        buffer.write(obj)
        buffer.write(b"\nendobj\n")

    xref_start = buffer.tell()
    buffer.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    buffer.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buffer.write(f"{off:010d} 00000 n \n".encode("ascii"))
    buffer.write(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
    )
    return buffer.getvalue()


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
    export_id = ""
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
            export_id = store_export_result(result)
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
        export_id=export_id,
        scan_types=SCAN_TYPES,
        severities=SEVERITIES,
        summary_order=SUMMARY_ORDER,
        tool_banner=TOOL_BANNER,
    )


@app.route("/export/csv/<export_id>", methods=["GET"])
def export_csv(export_id: str):
    result = get_export_result(export_id)
    if not result:
        abort(404, description="Report not found. Run a new scan and try export again.")

    payload = build_csv_report(result)
    scan_type = safe_filename_fragment(result.get("scan_type", "scan"))
    generated = safe_filename_fragment(result.get("generated_at_utc", "report"))
    filename = f"vscanner_{scan_type}_{generated}.csv"
    response = Response(payload, content_type="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/export/pdf/<export_id>", methods=["GET"])
def export_pdf(export_id: str):
    result = get_export_result(export_id)
    if not result:
        abort(404, description="Report not found. Run a new scan and try export again.")

    payload = build_pdf_report(result)
    scan_type = safe_filename_fragment(result.get("scan_type", "scan"))
    generated = safe_filename_fragment(result.get("generated_at_utc", "report"))
    filename = f"vscanner_{scan_type}_{generated}.pdf"
    response = Response(payload, mimetype="application/pdf")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
