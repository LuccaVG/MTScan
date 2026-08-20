#!/usr/bin/env python3
"""
Local MTScan web app.

The server intentionally uses Python's standard library so the app can run on a
fresh toolkit install without adding a web framework dependency. Scan execution
still goes through src.tool_runner rather than shelling out to the CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import datetime as _dt
import ipaddress
import json
import mimetypes
import re
import secrets
import threading
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from time import monotonic
from typing import Dict, List, Optional, Sequence, cast
from urllib.parse import unquote, urlparse

if __package__ in (None, ""):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src import browser_opener
    from src import scan_storage
    from src import tool_runner
else:
    from . import browser_opener
    from . import scan_storage
    from . import tool_runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = PROJECT_ROOT / "web"
WEB_ROOT_RESOLVED = WEB_ROOT.resolve()
MAX_BODY_BYTES = 64 * 1024
MAX_LOG_LINES = 2000
MAX_RETAINED_JOBS = 100
HEALTH_CACHE_SECONDS = 10.0
SCHEDULER_TICK_SECONDS = 10.0
SESSION_SECONDS = 12 * 60 * 60
AUTH_ITERATIONS = 200_000
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = secrets.token_urlsafe(18)
MIN_PASSWORD_LENGTH = 8
SESSION_COOKIE_NAME = "mtscan_session"
SCAN_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")
SCHEDULE_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")
WINDOWS_PATH_PATTERN = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|]+")
UNIX_PATH_PATTERN = re.compile(r"(?<!:)\/(?:home|root|tmp|var|opt|mnt|Users|usr)\/[^\s\"'<>|]+")
SECRET_VALUE_PATTERN = re.compile(r"(?i)\b(authorization|cookie|token|api[-_]?key|secret|password)(\s*[:=]\s*)([^\s,;]+)")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SCAN_MODES = {"chain", "naabu", "httpx", "nuclei"}
PROFILE_NAMES = {"default", "fast", "stealth", "deep"}
PROFILE_OPTIONS: Dict[str, Dict[str, object]] = {
    "default": {
        "top_ports": "1000",
        "severity": "critical,high,medium",
        "tags": "exposure,misconfig",
        "protocol_types": "http",
        "nuclei_rate_limit": 75,
        "nuclei_timeout": 8,
        "nuclei_retries": 0,
        "concurrency": 10,
        "parallel_processing": 10,
        "nuclei_run_timeout": 900,
        "no_interactsh": True,
        "disable_update_check": True,
        "title": True,
        "status_code": True,
        "tech_detect": True,
        "web_server": True,
    },
    "fast": {
        "top_ports": "100",
        "rate": 2000,
        "threads": 50,
        "timeout": 300,
        "severity": "critical,high",
        "tags": "exposure,misconfig,panel",
        "protocol_types": "http",
        "nuclei_rate_limit": 100,
        "nuclei_timeout": 6,
        "nuclei_retries": 0,
        "concurrency": 8,
        "parallel_processing": 8,
        "nuclei_run_timeout": 600,
        "no_interactsh": True,
        "disable_update_check": True,
        "title": True,
        "status_code": True,
        "tech_detect": True,
    },
    "stealth": {
        "top_ports": "1000",
        "rate": 10,
        "threads": 25,
        "scan_type": "connect",
        "severity": "critical,high,medium",
        "tags": "exposure,misconfig",
        "protocol_types": "http",
        "nuclei_rate_limit": 5,
        "nuclei_timeout": 8,
        "nuclei_retries": 0,
        "concurrency": 5,
        "parallel_processing": 5,
        "nuclei_run_timeout": 900,
        "no_interactsh": True,
        "disable_update_check": True,
        "title": True,
        "status_code": True,
        "tech_detect": True,
    },
    "deep": {
        "ports": "all",
        "timeout": 1800,
        "severity": "critical,high,medium,low",
        "protocol_types": "http",
        "nuclei_rate_limit": 50,
        "nuclei_timeout": 10,
        "nuclei_retries": 0,
        "concurrency": 12,
        "parallel_processing": 12,
        "nuclei_run_timeout": 1800,
        "no_interactsh": True,
        "disable_update_check": True,
        "title": True,
        "status_code": True,
        "tech_detect": True,
        "web_server": True,
        "content_length": True,
        "response_time": True,
    },
}
OPTION_KEYS = {
    "ports",
    "top_ports",
    "threads",
    "rate",
    "timeout",
    "severity",
    "templates",
    "tags",
    "protocol_types",
    "nuclei_rate_limit",
    "nuclei_timeout",
    "nuclei_retries",
    "nuclei_run_timeout",
    "concurrency",
    "parallel_processing",
    "no_interactsh",
    "disable_update_check",
    "tool_silent",
    "follow_redirects",
    "content_length",
    "response_time",
    "force_tools",
}


class ScanJob:
    def __init__(self, target: str, mode: str, options: Dict[str, object], dry_run: bool, json_output: bool) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.mode = mode
        self.options = options
        self.dry_run = dry_run
        self.json_output = json_output
        self.status = "queued"
        self.created_at = _dt.datetime.now().isoformat(timespec="seconds")
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.output_dir: Optional[Path] = None
        self.error: Optional[str] = None
        self.lines: List[str] = []
        self.results: List[tool_runner.ToolResult] = []
        self.summary: Dict[str, object] = {}
        self.lock = threading.Lock()

    def add_line(self, line: str) -> None:
        text = str(line).rstrip()
        if not text:
            return
        with self.lock:
            self.lines.append(text)
            if len(self.lines) > MAX_LOG_LINES:
                self.lines = self.lines[-MAX_LOG_LINES:]

    def to_dict(self) -> Dict[str, object]:
        with self.lock:
            return {
                "id": self.id,
                "target": self.target,
                "mode": self.mode,
                "status": self.status,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "dry_run": self.dry_run,
                "json_output": self.json_output,
                "output_dir": public_artifact_name(self.output_dir),
                "error": public_error(self.error),
                "lines": sanitize_log_lines(self.lines),
                "results": serialize_results(self.results),
                "summary": public_summary(self.summary),
                "report_file": public_artifact_name(self.summary.get("report_file")),
            }


JOBS: Dict[str, ScanJob] = {}
JOBS_LOCK = threading.RLock()
STORE = scan_storage.create_store()
HEALTH_CACHE_LOCK = threading.Lock()
HEALTH_CACHE: Dict[str, object] = {"expires": 0.0, "payload": None}
AUTH_LOCK = threading.RLock()
SESSIONS: Dict[str, Dict[str, object]] = {}
SCHEDULE_LOCK = threading.RLock()
RUNNING_SCHEDULES: Dict[str, str] = {}
SCHEDULER_STOP = threading.Event()


def requested_tools_for_mode(mode: str) -> Sequence[str]:
    if mode == "chain":
        return tool_runner.SECURITY_TOOLS
    if mode in tool_runner.SECURITY_TOOLS:
        return (mode,)
    raise tool_runner.ScanInputError("Unknown scan mode.")


def as_bool(value: object, default: bool = False) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def is_loopback_bind_host(host: str) -> bool:
    value = host.strip().strip("[]").lower()
    if value in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def build_scan_options(payload: Dict[str, object]) -> Dict[str, object]:
    profile = str(payload.get("profile") or "default").lower()
    options = PROFILE_OPTIONS.get(profile, PROFILE_OPTIONS["default"]).copy()
    raw_options = payload.get("options")
    if isinstance(raw_options, dict):
        for key in OPTION_KEYS:
            value = raw_options.get(key)
            if value not in (None, ""):
                options[key] = value
    for key in (
        "tool_silent",
        "follow_redirects",
        "content_length",
        "response_time",
        "force_tools",
        "no_interactsh",
        "disable_update_check",
    ):
        if key in options:
            options[key] = as_bool(options[key])
    return options


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def parse_time(value: object) -> Optional[_dt.datetime]:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=None)
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def next_run_time(interval_hours: int, from_time: Optional[_dt.datetime] = None) -> str:
    base = from_time or _dt.datetime.now()
    return (base + _dt.timedelta(hours=interval_hours)).isoformat(timespec="seconds")


def password_hash(password: str, salt: Optional[str] = None, iterations: int = AUTH_ITERATIONS) -> Dict[str, object]:
    salt_text = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_text), iterations)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt_text,
        "hash": digest.hex(),
    }


def verify_password(record: Dict[str, object], password: str) -> bool:
    password_record = record.get("password")
    if not isinstance(password_record, dict):
        return False
    salt = str(password_record.get("salt") or "")
    expected = str(password_record.get("hash") or "")
    try:
        iterations = int(password_record.get("iterations") or AUTH_ITERATIONS)
        actual = password_hash(password, salt=salt, iterations=iterations).get("hash")
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(str(actual), expected)


def default_auth_record() -> Dict[str, object]:
    created_at = now_iso()
    return {
        "username": DEFAULT_USERNAME,
        "password": password_hash(DEFAULT_PASSWORD),
        "must_change_password": True,
        "created_at": created_at,
        "updated_at": created_at,
    }


def load_auth_record() -> Dict[str, object]:
    with AUTH_LOCK:
        try:
            record = STORE.get_auth()  # type: ignore[attr-defined]
        except Exception:
            record = None
        if isinstance(record, dict) and record.get("username") and record.get("password"):
            return record
        record = default_auth_record()
        print(f"[AUTH] Initial username: {DEFAULT_USERNAME}", flush=True)
        print(f"[AUTH] Initial one-time password: {DEFAULT_PASSWORD}", flush=True)
        print("[AUTH] Change this password after the first login.", flush=True)
        try:
            STORE.save_auth(record)  # type: ignore[attr-defined]
        except Exception:
            pass
        return record


def save_auth_record(record: Dict[str, object]) -> None:
    with AUTH_LOCK:
        record["updated_at"] = now_iso()
        STORE.save_auth(record)  # type: ignore[attr-defined]


def public_auth_state(record: Optional[Dict[str, object]] = None, authenticated: bool = True) -> Dict[str, object]:
    data = record or load_auth_record()
    return {
        "authenticated": authenticated,
        "username": str(data.get("username") or DEFAULT_USERNAME),
        "must_change_password": bool(data.get("must_change_password", True)),
    }


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with AUTH_LOCK:
        SESSIONS[token] = {
            "username": username,
            "expires": monotonic() + SESSION_SECONDS,
        }
    return token


def session_for_token(token: str) -> Optional[Dict[str, object]]:
    if not token:
        return None
    now = monotonic()
    with AUTH_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        expires = float(session.get("expires") or 0)
        if expires < now:
            SESSIONS.pop(token, None)
            return None
        session["expires"] = now + SESSION_SECONDS
        return session.copy()


def delete_session(token: str) -> None:
    if not token:
        return
    with AUTH_LOCK:
        SESSIONS.pop(token, None)


def validate_new_password(password: object) -> str:
    text = str(password or "")
    if len(text) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"New password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if text == DEFAULT_PASSWORD:
        raise ValueError("New password cannot be the default password.")
    return text


def clean_schedule_payload(payload: Dict[str, object], existing: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    source = existing.copy() if existing else {}
    source.update(payload)
    mode = str(source.get("mode") or "chain").lower()
    if mode not in SCAN_MODES:
        raise tool_runner.ScanInputError("Mode must be chain, naabu, httpx, or nuclei.")
    profile = str(source.get("profile") or "default").lower()
    if profile not in PROFILE_NAMES:
        profile = "default"
    raw_interval = source.get("interval_hours", 1)
    try:
        interval_hours = int(raw_interval)
    except (TypeError, ValueError):
        raise ValueError("Interval must be a number of hours.")
    if interval_hours < 1 or interval_hours > 720:
        raise ValueError("Interval must be between 1 and 720 hours.")

    options = build_scan_options({**source, "profile": profile})
    target = tool_runner.validate_scan_request(source.get("target"), options)
    created_at = str(source.get("created_at") or now_iso())
    enabled = as_bool(source.get("enabled"), True)
    schedule_id = str(source.get("id") or uuid.uuid4().hex[:12])
    if not SCHEDULE_ID_PATTERN.match(schedule_id):
        schedule_id = uuid.uuid4().hex[:12]
    existing_next = source.get("next_run_at")
    next_run_at = str(existing_next) if enabled and existing_next else (next_run_time(interval_hours) if enabled else "")
    name = str(source.get("name") or f"{target} {mode.upper()}").strip()

    return {
        "id": schedule_id,
        "name": name,
        "target": target,
        "mode": mode,
        "profile": profile,
        "options": options,
        "interval_hours": interval_hours,
        "enabled": enabled,
        "dry_run": as_bool(source.get("dry_run")),
        "json_output": as_bool(source.get("json_output"), True),
        "created_at": created_at,
        "updated_at": now_iso(),
        "last_run_at": source.get("last_run_at"),
        "next_run_at": next_run_at or None,
        "last_scan_id": source.get("last_scan_id"),
        "last_status": source.get("last_status"),
    }


def schedule_payload(schedule: Dict[str, object]) -> Dict[str, object]:
    return {
        "target": schedule.get("target"),
        "mode": schedule.get("mode") or "chain",
        "profile": schedule.get("profile") or "default",
        "dry_run": bool(schedule.get("dry_run")),
        "json_output": bool(schedule.get("json_output", True)),
        "options": schedule.get("options") if isinstance(schedule.get("options"), dict) else {},
    }


def public_artifact_name(value: object) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    name = PureWindowsPath(text).name if "\\" in text else Path(text).name
    return name or None


def public_error(value: object) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    allowed_fragments = (
        "Scanner execution requires",
        "Missing scanner tools",
        "Target is required",
        "Mode must be",
        "Request body",
        "Invalid request",
        "not found",
        "timed out",
        "exit code",
    )
    if any(fragment.lower() in text.lower() for fragment in allowed_fragments):
        return sanitize_log_line(text)
    return "Scan failed. Check the local server console for details."


def sanitize_log_line(line: object) -> str:
    text = tool_runner.ANSI_ESCAPE_PATTERN.sub("", str(line))
    text = SECRET_VALUE_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text)
    text = WINDOWS_PATH_PATTERN.sub("[path]", text)
    text = UNIX_PATH_PATTERN.sub("[path]", text)
    return text


def sanitize_log_lines(lines: Sequence[str]) -> List[str]:
    return [sanitize_log_line(line) for line in lines[-MAX_LOG_LINES:]]


def public_summary(summary: Dict[str, object]) -> Dict[str, object]:
    public: Dict[str, object] = {}
    for key in (
        "target",
        "open_ports",
        "open_port_targets",
        "http_services",
        "http_urls",
        "findings_total",
        "security_findings",
        "observations",
        "severity_counts",
        "category_counts",
        "cve_findings",
        "chart_data",
        "findings",
    ):
        if key in summary:
            public[key] = summary[key]
    report_file = public_artifact_name(summary.get("report_file"))
    if report_file:
        public["report_file"] = report_file
    return public


def serialize_results(results: Sequence[tool_runner.ToolResult]) -> List[Dict[str, object]]:
    return [
        {
            "tool": result.tool,
            "command_preview": tool_runner.redact_command(result.command),
            "success": result.success,
            "returncode": result.returncode,
            "error": public_error(result.error),
            "output_file": public_artifact_name(result.output_file),
            "dry_run": result.dry_run,
            "output_lines": len(result.output_lines),
        }
        for result in results
    ]


def public_result_record(result: object) -> Dict[str, object]:
    if not isinstance(result, dict):
        return {}
    command = result.get("command_preview") or result.get("command") or []
    if not isinstance(command, list):
        command = []
    return {
        "tool": result.get("tool"),
        "command_preview": tool_runner.redact_command(command),
        "success": bool(result.get("success", False)),
        "returncode": result.get("returncode"),
        "error": public_error(result.get("error")),
        "output_file": public_artifact_name(result.get("output_file")),
        "dry_run": bool(result.get("dry_run", False)),
        "output_lines": result.get("output_lines", 0),
    }


def public_scan_record(scan: Dict[str, object]) -> Dict[str, object]:
    raw_results = scan.get("results")
    raw_summary = scan.get("summary")
    raw_lines = scan.get("lines")

    results = cast(List[object], raw_results) if isinstance(raw_results, list) else []
    summary = cast(Dict[str, object], raw_summary) if isinstance(raw_summary, dict) else {}
    lines = [str(line) for line in cast(List[object], raw_lines)] if isinstance(raw_lines, list) else []
    report_file = scan.get("report_file") or summary.get("report_file")

    return {
        "id": str(scan.get("id") or ""),
        "target": str(scan.get("target") or ""),
        "mode": str(scan.get("mode") or "chain"),
        "status": str(scan.get("status") or "completed"),
        "created_at": scan.get("created_at"),
        "started_at": scan.get("started_at"),
        "finished_at": scan.get("finished_at"),
        "dry_run": bool(scan.get("dry_run", False)),
        "json_output": bool(scan.get("json_output", True)),
        "output_dir": public_artifact_name(scan.get("output_dir")),
        "error": public_error(scan.get("error")),
        "lines": sanitize_log_lines(lines),
        "results": [public_result_record(result) for result in results],
        "summary": public_summary(summary),
        "report_file": public_artifact_name(report_file),
        "storage": str(scan.get("storage") or ""),
    }


def report_file_for_output_dir(output_dir: Optional[Path]) -> Optional[str]:
    if not output_dir:
        return None
    report = output_dir / tool_runner.REPORT_FILENAME
    return report.name if report.exists() else None


def persisted_scans(limit: int = 100) -> List[Dict[str, object]]:
    try:
        scans = STORE.list_scans(limit=limit)  # type: ignore[attr-defined]
    except Exception:
        return []
    if not isinstance(scans, list):
        return []
    return [public_scan_record(scan) for scan in scans if isinstance(scan, dict)]


def persisted_scan(scan_id: str) -> Optional[Dict[str, object]]:
    try:
        scan = STORE.get_scan(scan_id)  # type: ignore[attr-defined]
    except Exception:
        return None
    return public_scan_record(scan) if isinstance(scan, dict) else None


def stored_schedules(limit: int = 200) -> List[Dict[str, object]]:
    try:
        schedules = STORE.list_schedules(limit=limit)  # type: ignore[attr-defined]
    except Exception:
        return []
    if not isinstance(schedules, list):
        return []
    return [schedule for schedule in schedules if isinstance(schedule, dict)]


def stored_schedule(schedule_id: str) -> Optional[Dict[str, object]]:
    try:
        schedule = STORE.get_schedule(schedule_id)  # type: ignore[attr-defined]
    except Exception:
        return None
    return schedule if isinstance(schedule, dict) else None


def save_schedule(schedule: Dict[str, object]) -> Dict[str, object]:
    STORE.save_schedule(schedule)  # type: ignore[attr-defined]
    return schedule


def delete_stored_schedule(schedule_id: str) -> bool:
    try:
        return bool(STORE.delete_schedule(schedule_id))  # type: ignore[attr-defined]
    except Exception:
        return False


def merged_scan_history() -> List[Dict[str, object]]:
    with JOBS_LOCK:
        active = [public_scan_record(job.to_dict()) for job in JOBS.values()]
    merged: Dict[str, Dict[str, object]] = {}
    for scan in persisted_scans():
        scan_id = str(scan.get("id") or "")
        if scan_id:
            merged[scan_id] = scan
    for scan in active:
        scan_id = str(scan.get("id") or "")
        if scan_id:
            merged[scan_id] = scan
    scans = list(merged.values())
    scans.sort(key=lambda item: str(item.get("finished_at") or item.get("created_at") or ""), reverse=True)
    return scans


def scan_sort_time(scan: Dict[str, object]) -> str:
    return str(scan.get("finished_at") or scan.get("started_at") or scan.get("created_at") or "")


def finding_severity(finding: Dict[str, object]) -> str:
    return str(finding.get("severity") or "unknown").lower()


def aggregate_findings(scans: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for scan in scans:
        summary = scan.get("summary")
        if not isinstance(summary, dict):
            continue
        findings = summary.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            rows.append({
                "scan_id": scan.get("id"),
                "target": scan.get("target"),
                "scan_status": scan.get("status"),
                "scan_finished_at": scan.get("finished_at") or scan.get("created_at"),
                "severity": finding.get("severity") or "unknown",
                "category": finding.get("category") or "Finding",
                "name": finding.get("name") or finding.get("template_id") or "Finding",
                "cve": finding.get("cve") or "N/A",
                "matched_at": finding.get("matched_at") or scan.get("target"),
            })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda row: (severity_order.get(finding_severity(row), 9), str(row.get("scan_finished_at") or "")), reverse=False)
    return rows


def aggregate_assets(scans: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    by_target: Dict[str, List[Dict[str, object]]] = {}
    for scan in scans:
        target = str(scan.get("target") or "")
        if target:
            by_target.setdefault(target, []).append(scan)

    assets: List[Dict[str, object]] = []
    for target, target_scans in by_target.items():
        target_scans.sort(key=scan_sort_time, reverse=True)
        latest = target_scans[0]
        previous = target_scans[1] if len(target_scans) > 1 else {}
        latest_summary = latest.get("summary") if isinstance(latest.get("summary"), dict) else {}
        previous_summary = previous.get("summary") if isinstance(previous.get("summary"), dict) else {}
        security_findings = int(latest_summary.get("security_findings") or 0)
        previous_findings = int(previous_summary.get("security_findings") or 0)
        assets.append({
            "target": target,
            "scan_count": len(target_scans),
            "last_scan_id": latest.get("id"),
            "last_scan_at": latest.get("finished_at") or latest.get("created_at"),
            "last_status": latest.get("status"),
            "open_ports": int(latest_summary.get("open_ports") or 0),
            "http_services": int(latest_summary.get("http_services") or 0),
            "security_findings": security_findings,
            "finding_delta": security_findings - previous_findings,
            "cve_findings": int(latest_summary.get("cve_findings") or 0),
        })
    assets.sort(key=lambda item: int(item.get("security_findings") or 0), reverse=True)
    return assets


def overview_payload() -> Dict[str, object]:
    scans = merged_scan_history()
    schedules = stored_schedules()
    findings = aggregate_findings(scans)
    assets = aggregate_assets(scans)
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    category_counts: Dict[str, int] = {}

    for scan in scans:
        summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
        raw_severity = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), dict) else {}
        for key, value in raw_severity.items():
            label = str(key or "unknown").lower()
            severity_counts[label] = severity_counts.get(label, 0) + int(value or 0)
        raw_categories = summary.get("category_counts") if isinstance(summary.get("category_counts"), dict) else {}
        for key, value in raw_categories.items():
            label = str(key or "Other")
            category_counts[label] = category_counts.get(label, 0) + int(value or 0)

    metrics = {
        "total_scans": len(scans),
        "total_assets": len(assets),
        "active_schedules": len([item for item in schedules if item.get("enabled")]),
        "security_findings": sum(int((scan.get("summary") or {}).get("security_findings") or 0) for scan in scans if isinstance(scan.get("summary"), dict)),
        "critical_findings": severity_counts.get("critical", 0),
        "high_findings": severity_counts.get("high", 0),
        "open_ports": sum(int((scan.get("summary") or {}).get("open_ports") or 0) for scan in scans if isinstance(scan.get("summary"), dict)),
        "http_services": sum(int((scan.get("summary") or {}).get("http_services") or 0) for scan in scans if isinstance(scan.get("summary"), dict)),
    }
    high_findings = [item for item in findings if finding_severity(item) in {"critical", "high"}]
    return {
        "metrics": metrics,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "latest_scan": scans[0] if scans else None,
        "recent_scans": scans[:20],
        "recent_high_findings": high_findings[:10],
        "findings": findings[:500],
        "assets": assets,
        "schedules": schedules,
        "health": health_payload(),
    }


def prune_jobs() -> None:
    with JOBS_LOCK:
        if len(JOBS) <= MAX_RETAINED_JOBS:
            return
        removable = [
            job for job in JOBS.values()
            if job.status not in {"queued", "running"}
        ]
        removable.sort(key=lambda job: job.finished_at or job.started_at or job.created_at)
        for job in removable[: max(0, len(JOBS) - MAX_RETAINED_JOBS)]:
            JOBS.pop(job.id, None)


def persist_job(job: ScanJob) -> None:
    data = job.to_dict()
    if data.get("dry_run"):
        return
    report_file = report_file_for_output_dir(job.output_dir)
    if report_file:
        data["report_file"] = report_file
        summary = data.get("summary")
        if isinstance(summary, dict):
            summary["report_file"] = report_file
    try:
        STORE.save_scan(data)  # type: ignore[attr-defined]
    except Exception as exc:
        job.add_line(f"Storage warning: {exc}")
    prune_jobs()


def _fresh_health_payload() -> Dict[str, object]:
    raw_tools = tool_runner.check_tools_status()
    tools = {
        tool: {
            "available": info.get("available"),
            "detail": sanitize_log_line(info.get("detail") or ""),
        }
        for tool, info in raw_tools.items()
    }
    missing = [tool for tool, info in tools.items() if info.get("available") != "yes"]
    try:
        raw_storage = STORE.status()  # type: ignore[attr-defined]
    except Exception as exc:
        raw_storage = {"backend": "unknown", "available": "no", "detail": str(exc)}
    storage = {
        "backend": raw_storage.get("backend"),
        "available": raw_storage.get("available"),
        "detail": sanitize_log_line(raw_storage.get("detail") or ""),
        "keyspace": raw_storage.get("keyspace"),
        "imported_file_history": raw_storage.get("imported_file_history"),
        "path": public_artifact_name(raw_storage.get("path")),
        "schedule_path": public_artifact_name(raw_storage.get("schedule_path")),
        "auth_path": public_artifact_name(raw_storage.get("auth_path")),
    }
    return {
        "platform": "linux" if tool_runner.is_linux() else "non-linux",
        "can_run_scans": tool_runner.is_linux() and not missing,
        "tools": tools,
        "missing_tools": missing,
        "storage": storage,
    }


def health_payload() -> Dict[str, object]:
    now = monotonic()
    with HEALTH_CACHE_LOCK:
        cached_payload = HEALTH_CACHE.get("payload")
        expires_value = HEALTH_CACHE.get("expires")
        expires = float(expires_value) if isinstance(expires_value, (int, float)) else 0.0
        if isinstance(cached_payload, dict) and now < expires:
            return cast(Dict[str, object], cached_payload)

    payload = _fresh_health_payload()
    with HEALTH_CACHE_LOCK:
        HEALTH_CACHE["payload"] = payload
        HEALTH_CACHE["expires"] = monotonic() + HEALTH_CACHE_SECONDS
    return payload


def startup_tool_check_messages(payload: Dict[str, object]) -> List[str]:
    lines = ["Checking scanner tools before starting web app..."]
    raw_tools = payload.get("tools")
    tools = cast(Dict[str, Dict[str, object]], raw_tools) if isinstance(raw_tools, dict) else {}

    for tool in tool_runner.SECURITY_TOOLS:
        raw_info = tools.get(tool, {})
        info = raw_info if isinstance(raw_info, dict) else {}
        available = info.get("available") == "yes"
        status = "OK" if available else "MISSING"
        detail = str(info.get("detail") or ("available" if available else "not found"))
        lines.append(f"  [{status}] {tool}: {detail}")

    raw_missing = payload.get("missing_tools")
    missing = [str(tool) for tool in raw_missing] if isinstance(raw_missing, list) else []
    if payload.get("platform") != "linux":
        lines.append("[WARN] Scanner execution requires a native Linux environment; dry runs and history can still be used.")
    if missing:
        lines.append(f"[WARN] Missing scanner tools: {', '.join(missing)}")
        lines.append("[WARN] Install missing tools before running live scans.")
    else:
        lines.append("[OK] All scanner tools are installed.")
    return lines


def print_startup_tool_check() -> None:
    for line in startup_tool_check_messages(health_payload()):
        print(line, flush=True)


def open_browser(url: str) -> None:
    opened = browser_opener.open_url(url)
    if opened:
        print("Opened MTScan in your browser.", flush=True)
    else:
        print(f"Open this URL in your browser: {url}", flush=True)


def create_job(payload: Dict[str, object]) -> ScanJob:
    mode = str(payload.get("mode") or "chain").lower()
    if mode not in SCAN_MODES:
        raise tool_runner.ScanInputError("Mode must be chain, naabu, httpx, or nuclei.")

    options = build_scan_options(payload)
    target = tool_runner.validate_scan_request(payload.get("target"), options)
    dry_run = as_bool(payload.get("dry_run"))
    json_output = as_bool(payload.get("json_output"), True)
    job = ScanJob(target, mode, options, dry_run, json_output)

    with JOBS_LOCK:
        JOBS[job.id] = job
    prune_jobs()

    thread = threading.Thread(target=run_job, args=(job,), daemon=True)
    thread.start()
    return job


def run_job(job: ScanJob) -> None:
    with job.lock:
        job.status = "running"
        job.started_at = _dt.datetime.now().isoformat(timespec="seconds")
        job.output_dir = tool_runner.default_output_dir(job.target)

    try:
        if not job.dry_run and not tool_runner.is_linux():
            raise RuntimeError("Scanner execution requires a native Linux environment. Enable dry run to preview commands here.")

        requested_tools = requested_tools_for_mode(job.mode)
        if not job.dry_run and not as_bool(job.options.get("force_tools")):
            status = tool_runner.check_tools_status()
            missing = [tool for tool in requested_tools if status.get(tool, {}).get("available") != "yes"]
            if missing:
                raise RuntimeError(f"Missing scanner tools: {', '.join(missing)}.")

        if job.mode == "chain":
            results = tool_runner.run_chain(
                job.target,
                output_dir=job.output_dir,
                save_output=True,
                json_output=job.json_output,
                dry_run=job.dry_run,
                on_line=job.add_line,
                **job.options,
            )
        else:
            result = tool_runner.run_tool(
                job.mode,
                job.target,
                output_dir=job.output_dir,
                save_output=True,
                json_output=job.json_output,
                dry_run=job.dry_run,
                on_line=job.add_line,
                **job.options,
            )
            results = [result]
            if job.output_dir and not job.dry_run:
                tool_runner.write_summary(job.output_dir, job.target, results)

        summary = tool_runner.summarize_scan_results(job.target, results)
        report_file = report_file_for_output_dir(job.output_dir)
        if report_file:
            summary["report_file"] = report_file
        with job.lock:
            job.results = list(results)
            job.summary = summary
            job.status = "completed" if all(result.success for result in results) else "failed"
    except Exception as exc:
        with job.lock:
            job.status = "failed"
            job.error = str(exc)
            job.lines.append(f"ERROR: {exc}")
            if len(job.lines) > MAX_LOG_LINES:
                job.lines = job.lines[-MAX_LOG_LINES:]
        traceback.print_exc()
    finally:
        with job.lock:
            job.finished_at = _dt.datetime.now().isoformat(timespec="seconds")
        persist_job(job)


def refresh_schedule_status(schedule_id: str, status: str, scan_id: Optional[str] = None) -> None:
    schedule = stored_schedule(schedule_id)
    if not schedule:
        return
    schedule["last_status"] = status
    if scan_id:
        schedule["last_scan_id"] = scan_id
    schedule["updated_at"] = now_iso()
    try:
        save_schedule(schedule)
    except Exception:
        traceback.print_exc()


def watch_schedule_job(schedule_id: str, scan_id: str) -> None:
    final_status = "unknown"
    try:
        while not SCHEDULER_STOP.wait(2.0):
            with JOBS_LOCK:
                job = JOBS.get(scan_id)
            if not job:
                stored = persisted_scan(scan_id)
                if stored:
                    final_status = str(stored.get("status") or "completed")
                    break
                continue
            with job.lock:
                status = job.status
            if status not in {"queued", "running"}:
                final_status = status
                break
    finally:
        refresh_schedule_status(schedule_id, final_status, scan_id)
        with SCHEDULE_LOCK:
            RUNNING_SCHEDULES.pop(schedule_id, None)


def start_schedule_scan(schedule: Dict[str, object], manual: bool = False) -> ScanJob:
    schedule_id = str(schedule.get("id") or "")
    if not schedule_id:
        raise ValueError("Schedule not found.")
    with SCHEDULE_LOCK:
        if schedule_id in RUNNING_SCHEDULES:
            raise RuntimeError("Schedule already has a running scan.")
        RUNNING_SCHEDULES[schedule_id] = ""

    try:
        job = create_job(schedule_payload(schedule))
        interval = int(schedule.get("interval_hours") or 1)
        run_time = now_iso()
        schedule["last_run_at"] = run_time
        schedule["last_scan_id"] = job.id
        schedule["last_status"] = "queued"
        schedule["next_run_at"] = next_run_time(interval)
        schedule["updated_at"] = run_time
        save_schedule(schedule)
        with SCHEDULE_LOCK:
            RUNNING_SCHEDULES[schedule_id] = job.id
        watcher = threading.Thread(target=watch_schedule_job, args=(schedule_id, job.id), daemon=True)
        watcher.start()
        return job
    except Exception:
        with SCHEDULE_LOCK:
            RUNNING_SCHEDULES.pop(schedule_id, None)
        schedule["last_status"] = "failed"
        schedule["updated_at"] = now_iso()
        try:
            save_schedule(schedule)
        except Exception:
            pass
        raise


def reschedule_missed_schedules() -> None:
    now = _dt.datetime.now()
    for schedule in stored_schedules():
        if not schedule.get("enabled"):
            continue
        next_time = parse_time(schedule.get("next_run_at"))
        if next_time and next_time > now:
            continue
        schedule["next_run_at"] = next_run_time(int(schedule.get("interval_hours") or 1), now)
        schedule["updated_at"] = now_iso()
        try:
            save_schedule(schedule)
        except Exception:
            traceback.print_exc()


def scheduler_loop() -> None:
    reschedule_missed_schedules()
    while not SCHEDULER_STOP.wait(SCHEDULER_TICK_SECONDS):
        now = _dt.datetime.now()
        for schedule in stored_schedules():
            if not schedule.get("enabled"):
                continue
            due = parse_time(schedule.get("next_run_at"))
            if not due or due > now:
                continue
            try:
                start_schedule_scan(schedule)
            except RuntimeError:
                continue
            except Exception:
                traceback.print_exc()


def start_scheduler() -> threading.Thread:
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    return thread


class MTScanHandler(BaseHTTPRequestHandler):
    server_version = "MTScanApp"

    def version_string(self) -> str:
        return self.server_version

    def request_host_allowed(self) -> bool:
        host_header = (self.headers.get("Host") or "").strip().lower()
        if not host_header:
            return True
        if host_header.startswith("[") and "]" in host_header:
            host = host_header[1:].split("]", 1)[0]
        elif host_header.count(":") == 1:
            host = host_header.rsplit(":", 1)[0]
        else:
            host = host_header
        host = host.rstrip(".")
        allowed_hosts = getattr(self.server, "allowed_hosts", LOOPBACK_HOSTS)
        if "*" in allowed_hosts:
            return True
        return host in allowed_hosts

    def reject_if_forbidden_host(self) -> bool:
        if self.request_host_allowed():
            return False
        self.write_json({"error": "Forbidden."}, HTTPStatus.FORBIDDEN)
        return True

    def cookie_token(self) -> str:
        raw_cookie = self.headers.get("Cookie") or ""
        for item in raw_cookie.split(";"):
            if "=" not in item:
                continue
            key, value = item.strip().split("=", 1)
            if key == SESSION_COOKIE_NAME:
                return value
        return ""

    def current_session(self) -> Optional[Dict[str, object]]:
        return session_for_token(self.cookie_token())

    def set_session_header(self, token: str) -> str:
        return f"{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"

    def clear_session_header(self) -> str:
        return f"{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"

    def require_api_auth(self, path: str) -> bool:
        if not path.startswith("/api/"):
            return True
        if path in {"/api/session", "/api/login"}:
            return True
        if path == "/api/logout":
            return True
        session = self.current_session()
        if not session:
            self.write_json({"error": "Authentication required.", "authenticated": False}, HTTPStatus.UNAUTHORIZED)
            return False
        auth = load_auth_record()
        if bool(auth.get("must_change_password")) and path != "/api/change-password":
            self.write_json(
                {
                    "error": "Password change required.",
                    "authenticated": True,
                    "must_change_password": True,
                },
                HTTPStatus.FORBIDDEN,
            )
            return False
        return True

    def handle_session(self) -> None:
        session = self.current_session()
        if not session:
            self.write_json({"authenticated": False, "must_change_password": False})
            return
        self.write_json(public_auth_state(load_auth_record()))

    def handle_login(self) -> None:
        try:
            payload = self.read_json_body()
        except ValueError as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        auth = load_auth_record()
        if username != str(auth.get("username") or DEFAULT_USERNAME) or not verify_password(auth, password):
            self.write_json({"error": "Invalid username or password."}, HTTPStatus.UNAUTHORIZED)
            return
        token = create_session(username)
        self.write_json(public_auth_state(auth), extra_headers={"Set-Cookie": self.set_session_header(token)})

    def handle_logout(self) -> None:
        delete_session(self.cookie_token())
        self.write_json(
            {"authenticated": False, "must_change_password": False},
            extra_headers={"Set-Cookie": self.clear_session_header()},
        )

    def handle_change_password(self) -> None:
        if not self.current_session():
            self.write_json({"error": "Authentication required."}, HTTPStatus.UNAUTHORIZED)
            return
        try:
            payload = self.read_json_body()
            current_password = str(payload.get("current_password") or "")
            new_password = validate_new_password(payload.get("new_password"))
            confirm_password = payload.get("confirm_password")
            if confirm_password is not None and str(confirm_password) != new_password:
                raise ValueError("Password confirmation does not match.")
            auth = load_auth_record()
            if not verify_password(auth, current_password):
                self.write_json({"error": "Current password is incorrect."}, HTTPStatus.BAD_REQUEST)
                return
            auth["password"] = password_hash(new_password)
            auth["must_change_password"] = False
            auth["password_changed_at"] = now_iso()
            save_auth_record(auth)
            self.write_json(public_auth_state(auth))
        except ValueError as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception:
            traceback.print_exc()
            self.write_json({"error": "Could not update password."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_GET(self) -> None:
        if self.reject_if_forbidden_host():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/session":
            self.handle_session()
            return
        if not self.require_api_auth(parsed.path):
            return
        if parsed.path == "/api/overview":
            self.write_json(overview_payload())
            return
        if parsed.path == "/api/health":
            self.write_json(health_payload())
            return
        if parsed.path == "/api/schedules":
            self.write_json({"schedules": stored_schedules()})
            return
        if parsed.path.startswith("/api/schedules/"):
            schedule_id = parsed.path.rsplit("/", 1)[-1]
            if not SCHEDULE_ID_PATTERN.match(schedule_id):
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            schedule = stored_schedule(schedule_id)
            if not schedule:
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            self.write_json(schedule)
            return
        if parsed.path == "/api/scans":
            self.write_json({"scans": merged_scan_history()})
            return
        if parsed.path.startswith("/api/scans/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            if not SCAN_ID_PATTERN.match(scan_id):
                self.write_json({"error": "Scan not found."}, HTTPStatus.NOT_FOUND)
                return
            with JOBS_LOCK:
                job = JOBS.get(scan_id)
            if job:
                self.write_json(job.to_dict())
                return
            stored = persisted_scan(scan_id)
            if not stored:
                self.write_json({"error": "Scan not found."}, HTTPStatus.NOT_FOUND)
                return
            self.write_json(stored)
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:
        if self.reject_if_forbidden_host():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            self.handle_login()
            return
        if parsed.path == "/api/logout":
            self.handle_logout()
            return
        if parsed.path == "/api/change-password":
            self.handle_change_password()
            return
        if not self.require_api_auth(parsed.path):
            return
        if parsed.path == "/api/schedules":
            try:
                payload = self.read_json_body()
                schedule = save_schedule(clean_schedule_payload(payload))
                self.write_json(schedule, HTTPStatus.CREATED)
            except tool_runner.ScanInputError as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except ValueError as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path.startswith("/api/schedules/") and parsed.path.endswith("/run"):
            schedule_id = parsed.path.split("/")[-2]
            if not SCHEDULE_ID_PATTERN.match(schedule_id):
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            schedule = stored_schedule(schedule_id)
            if not schedule:
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            try:
                job = start_schedule_scan(schedule, manual=True)
                self.write_json({"scan": job.to_dict(), "schedule": stored_schedule(schedule_id)})
            except RuntimeError as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except (tool_runner.ScanInputError, ValueError) as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path != "/api/scans":
            self.write_json({"error": "Endpoint not found."}, HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self.read_json_body()
            job = create_job(payload)
            self.write_json(job.to_dict(), HTTPStatus.CREATED)
        except tool_runner.ScanInputError as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except ValueError as exc:
            self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_OPTIONS(self) -> None:
        if self.reject_if_forbidden_host():
            return
        self.write_json({"error": "Method not allowed."}, HTTPStatus.METHOD_NOT_ALLOWED)

    def do_PUT(self) -> None:
        if self.reject_if_forbidden_host():
            return
        self.write_json({"error": "Method not allowed."}, HTTPStatus.METHOD_NOT_ALLOWED)

    def do_PATCH(self) -> None:
        if self.reject_if_forbidden_host():
            return
        parsed = urlparse(self.path)
        if not self.require_api_auth(parsed.path):
            return
        if parsed.path.startswith("/api/schedules/"):
            schedule_id = parsed.path.rsplit("/", 1)[-1]
            if not SCHEDULE_ID_PATTERN.match(schedule_id):
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            existing = stored_schedule(schedule_id)
            if not existing:
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            try:
                payload = self.read_json_body()
                payload["id"] = schedule_id
                if any(key in payload for key in ("interval_hours", "enabled", "target", "mode", "profile", "options", "dry_run", "json_output")):
                    payload["next_run_at"] = None
                schedule = save_schedule(clean_schedule_payload(payload, existing))
                self.write_json(schedule)
            except tool_runner.ScanInputError as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except ValueError as exc:
                self.write_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.write_json({"error": "Method not allowed."}, HTTPStatus.METHOD_NOT_ALLOWED)

    def do_DELETE(self) -> None:
        if self.reject_if_forbidden_host():
            return
        parsed = urlparse(self.path)
        if not self.require_api_auth(parsed.path):
            return
        if parsed.path.startswith("/api/schedules/"):
            schedule_id = parsed.path.rsplit("/", 1)[-1]
            if not SCHEDULE_ID_PATTERN.match(schedule_id):
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            with SCHEDULE_LOCK:
                if schedule_id in RUNNING_SCHEDULES:
                    self.write_json({"error": "Schedule has a running scan."}, HTTPStatus.CONFLICT)
                    return
            if not delete_stored_schedule(schedule_id):
                self.write_json({"error": "Schedule not found."}, HTTPStatus.NOT_FOUND)
                return
            self.write_json({"deleted": True})
            return
        self.write_json({"error": "Method not allowed."}, HTTPStatus.METHOD_NOT_ALLOWED)

    def read_json_body(self) -> Dict[str, object]:
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type and content_type != "application/json":
            raise ValueError("Request body must be application/json.")
        length_text = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_text)
        except ValueError:
            raise ValueError("Invalid request length.")
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("Request body is too large.")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError("Request body must be valid JSON.")
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object.")
        return data

    def serve_static(self, request_path: str) -> None:
        relative = unquote(request_path).lstrip("/") or "index.html"
        if "\\" in relative or "\x00" in relative:
            self.write_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            return
        if relative.endswith("/"):
            relative += "index.html"
        root = WEB_ROOT_RESOLVED
        path = (WEB_ROOT / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            self.write_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            return
        if not path.is_file():
            self.write_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_security_headers()
        self.end_headers()
        self.safe_write(data)

    def send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )

    def write_json(
        self,
        data: Dict[str, object],
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        payload = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_security_headers()
        self.end_headers()
        self.safe_write(payload)

    def safe_write(self, payload: bytes) -> None:
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, _format: str, *args: object) -> None: # type: ignore
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MTScan local web app")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--allow-remote", action="store_true", help="Allow binding the app to a non-loopback interface")
    parser.add_argument(
        "--skip-tool-check",
        action="store_true",
        help="Skip the startup scanner tool check when the caller already performed it",
    )
    parser.add_argument("--no-browser", action="store_true", help="Do not try to open the dashboard automatically")
    args = parser.parse_args()

    if not args.allow_remote and not is_loopback_bind_host(args.host):
        raise SystemExit("Refusing non-loopback bind without --allow-remote.")

    if not args.skip_tool_check:
        print_startup_tool_check()

    load_auth_record()

    try:
        server = ThreadingHTTPServer((args.host, args.port), MTScanHandler)
    except OSError as exc:
        raise SystemExit(f"Could not start MTScan app on {args.host}:{args.port}: {exc}") from exc
    allowed_hosts = {host.lower() for host in LOOPBACK_HOSTS}
    allowed_hosts.add(args.host.strip().strip("[]").lower())
    if args.allow_remote:
        allowed_hosts.add("*")
    server.allowed_hosts = allowed_hosts  # type: ignore[attr-defined]
    url = f"http://{args.host}:{args.port}"
    print(f"MTScan app listening at {url}")
    if not args.no_browser:
        open_browser(url)
    start_scheduler()
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MTScan app.")
    finally:
        SCHEDULER_STOP.set()
        server.server_close()


if __name__ == "__main__":
    main()
