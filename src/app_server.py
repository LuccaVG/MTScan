#!/usr/bin/env python3
"""
Local MTScan web app.

The server intentionally uses Python's standard library so the app can run on a
fresh toolkit install without adding a web framework dependency. Scan execution
still goes through src.tool_runner rather than shelling out to the CLI.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import mimetypes
import threading
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote, urlparse

if __package__ in (None, ""):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src import tool_runner
else:
    from . import tool_runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = PROJECT_ROOT / "web"
MAX_BODY_BYTES = 64 * 1024
MAX_LOG_LINES = 2000
SCAN_MODES = {"chain", "naabu", "httpx", "nuclei"}
PROFILE_OPTIONS: Dict[str, Dict[str, object]] = {
    "default": {
        "top_ports": "1000",
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
        "title": True,
        "status_code": True,
        "tech_detect": True,
    },
    "stealth": {
        "top_ports": "1000",
        "rate": 10,
        "threads": 25,
        "scan_type": "connect",
        "nuclei_rate_limit": 5,
        "concurrency": 5,
        "parallel_processing": 5,
        "no_interactsh": True,
        "title": True,
        "status_code": True,
        "tech_detect": True,
    },
    "deep": {
        "ports": "all",
        "timeout": 1800,
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
                "output_dir": str(self.output_dir) if self.output_dir else None,
                "error": self.error,
                "lines": list(self.lines),
                "results": serialize_results(self.results),
                "summary": self.summary,
            }


JOBS: Dict[str, ScanJob] = {}
JOBS_LOCK = threading.Lock()


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


def build_scan_options(payload: Dict[str, object]) -> Dict[str, object]:
    profile = str(payload.get("profile") or "default").lower()
    options = PROFILE_OPTIONS.get(profile, PROFILE_OPTIONS["default"]).copy()
    raw_options = payload.get("options")
    if isinstance(raw_options, dict):
        for key in OPTION_KEYS:
            value = raw_options.get(key)
            if value not in (None, ""):
                options[key] = value
    for key in ("tool_silent", "follow_redirects", "content_length", "response_time", "force_tools"):
        if key in options:
            options[key] = as_bool(options[key])
    return options


def serialize_results(results: Sequence[tool_runner.ToolResult]) -> List[Dict[str, object]]:
    return [
        {
            "tool": result.tool,
            "command": result.command,
            "success": result.success,
            "returncode": result.returncode,
            "error": result.error,
            "output_file": str(result.output_file) if result.output_file else None,
            "dry_run": result.dry_run,
            "output_lines": len(result.output_lines),
        }
        for result in results
    ]


def health_payload() -> Dict[str, object]:
    tools = tool_runner.check_tools_status()
    missing = [tool for tool, info in tools.items() if info.get("available") != "yes"]
    return {
        "platform": "linux" if tool_runner.is_linux() else "non-linux",
        "can_run_scans": tool_runner.is_linux() and not missing,
        "tools": tools,
        "missing_tools": missing,
    }


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


class MTScanHandler(BaseHTTPRequestHandler):
    server_version = "MTScanApp/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.write_json(health_payload())
            return
        if parsed.path == "/api/scans":
            with JOBS_LOCK:
                scans = [job.to_dict() for job in JOBS.values()]
            scans.sort(key=lambda item: str(item.get("created_at")), reverse=True)
            self.write_json({"scans": scans})
            return
        if parsed.path.startswith("/api/scans/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(scan_id)
            if not job:
                self.write_json({"error": "Scan not found."}, HTTPStatus.NOT_FOUND)
                return
            self.write_json(job.to_dict())
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
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

    def read_json_body(self) -> Dict[str, object]:
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
        if relative.endswith("/"):
            relative += "index.html"
        root = WEB_ROOT.resolve()
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
        self.end_headers()
        self.wfile.write(data)

    def write_json(self, data: Dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None: # type: ignore
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MTScan local web app")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), MTScanHandler)
    url = f"http://{args.host}:{args.port}"
    print(f"MTScan app listening at {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MTScan app.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
