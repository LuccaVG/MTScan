#!/usr/bin/env python3
"""
Shared execution layer for MTScan tools.

This module owns executable discovery, command construction, streaming output,
and the sequential naabu -> httpx -> nuclei workflow. CLI, menu, and wrappers
should route through here so tool behavior stays consistent.
"""

from __future__ import annotations

import datetime as _dt
import csv
import json
import os
import platform
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, cast


SECURITY_TOOLS = ("naabu", "httpx", "nuclei")


@dataclass
class ToolResult:
    tool: str
    command: List[str]
    success: bool
    returncode: Optional[int] = None
    output_lines: List[str] = field(default_factory=list)
    output_file: Optional[Path] = None
    error: Optional[str] = None
    dry_run: bool = False


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_output_dir(target: str) -> Path:
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in target)
    return project_root() / f"results_{safe_target}_{timestamp}"


def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def output_path_for(tool: str, output_dir: Path, json_output: bool = False, csv_output: bool = False) -> Path:
    """Return the conventional output path for a tool result."""
    if csv_output:
        suffix = "csv"
    elif tool == "nuclei" and json_output:
        suffix = "jsonl"
    elif json_output:
        suffix = "json"
    else:
        suffix = "txt"
    return output_dir / f"{tool}_results.{suffix}"


def _candidate_paths(tool_name: str) -> List[Path]:
    names = [tool_name]
    if tool_name == "httpx":
        names.append("httpx-toolkit")

    paths: List[Path] = []
    for name in names:
        found = shutil.which(name)
        if found:
            paths.append(Path(found))

    home = Path.home()
    common_dirs = [
        Path("/usr/bin"),
        Path("/usr/local/bin"),
        Path("/snap/bin"),
        Path("/root/go/bin"),
        home / "go" / "bin",
        home / ".local" / "bin",
        Path("/opt") / tool_name,
    ]

    for directory in common_dirs:
        for name in names:
            paths.append(directory / name)

    seen = set()
    unique: List[Path] = []
    for path in paths:
        text = str(path)
        if text not in seen:
            seen.add(text)
            unique.append(path)
    return unique


def get_executable_path(tool_name: str) -> Optional[str]:
    """Find a ProjectDiscovery executable across common Linux install paths."""
    for path in _candidate_paths(tool_name):
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except OSError:
            continue
    return None


def get_tool_help(tool_path: str) -> str:
    for flag in ("-h", "--help"):
        try:
            result = subprocess.run(
                [tool_path, flag],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.stdout or result.stderr:
                return f"{result.stdout}\n{result.stderr}"
        except Exception:
            continue
    return ""


def verify_tool(tool_name: str) -> Tuple[bool, Optional[str], Optional[str]]:
    path = get_executable_path(tool_name)
    if not path:
        return False, None, "not found"

    for flag in ("-version", "--version", "-h", "--help"):
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                version = (result.stdout or result.stderr).strip().splitlines()
                return True, path, version[0] if version else None
        except Exception:
            continue
    return False, path, "found but did not respond to version/help checks"


def check_tools_status() -> Dict[str, Dict[str, Optional[str]]]:
    status: Dict[str, Dict[str, Optional[str]]] = {}
    for tool in SECURITY_TOOLS:
        available, path, detail = verify_tool(tool)
        status[tool] = {
            "available": "yes" if available else "no",
            "path": path,
            "detail": detail,
        }
    return status


def check_network_connectivity(timeout: int = 5) -> bool:
    checks = [
        ("socket", ("8.8.8.8", 53)),
        ("socket", ("1.1.1.1", 53)),
        ("dns", "github.com"),
        ("dns", "cloudflare.com"),
        ("http", "https://github.com"),
    ]

    for kind, target in checks:
        try:
            if kind == "socket":
                host, port = target  # type: ignore[misc]
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            elif kind == "dns":
                socket.gethostbyname(str(target))
                return True
            elif kind == "http":
                urllib.request.urlopen(str(target), timeout=timeout)
                return True
        except Exception:
            continue
    return False


def normalize_ports(ports: Optional[str], top_ports: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Return (flag, value) for naabu port selection."""
    if ports:
        value = str(ports).strip()
        if value.startswith("top-"):
            _, number = value.split("-", 1)
            return "-top-ports", number
        if value.lower() == "all":
            return "-p", "1-65535"
        return "-p", value

    if top_ports:
        return "-top-ports", str(top_ports).strip()

    return "-top-ports", "1000"


def _append_pair(cmd: List[str], flag: str, value: Optional[object]) -> None:
    if value is not None and str(value) != "":
        cmd.extend([flag, str(value)])


def _append_bool(cmd: List[str], flag: str, enabled: bool) -> None:
    if enabled:
        cmd.append(flag)


def build_naabu_command(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    ports: Optional[str] = None,
    top_ports: Optional[str] = None,
    exclude_ports: Optional[str] = None,
    threads: Optional[int] = None,
    rate: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    scan_type: Optional[str] = None,
    output_file: Optional[Path] = None,
    json_output: bool = False,
    csv_output: bool = False,
    silent: bool = False,
    no_color: bool = True,
    extra_args: Optional[Sequence[str]] = None,
    tool_path: Optional[str] = None,
) -> List[str]:
    path = tool_path or get_executable_path("naabu") or "naabu"
    cmd = [path]

    if target:
        cmd.extend(["-host", target])
    elif target_list:
        cmd.extend(["-l", target_list])
    else:
        raise ValueError("naabu requires target or target_list")

    port_flag, port_value = normalize_ports(ports, top_ports)
    if port_flag and port_value:
        cmd.extend([port_flag, port_value])

    _append_pair(cmd, "-exclude-ports", exclude_ports)
    _append_pair(cmd, "-c", threads)
    _append_pair(cmd, "-rate", rate)
    _append_pair(cmd, "-timeout", timeout)
    _append_pair(cmd, "-retries", retries)
    _append_pair(cmd, "-scan-type", scan_type or "connect")

    if output_file:
        cmd.extend(["-o", str(output_file)])
    _append_bool(cmd, "-json", json_output)
    _append_bool(cmd, "-csv", csv_output)
    _append_bool(cmd, "-silent", silent)
    _append_bool(cmd, "-no-color", no_color)

    if extra_args:
        cmd.extend([str(arg) for arg in extra_args if str(arg)])
    return cmd


def _httpx_target_args(_tool_path: str, target: Optional[str], target_list: Optional[str]) -> List[str]:
    if target_list:
        return ["-l", target_list]
    if not target:
        raise ValueError("httpx requires target or target_list")
    return ["-u", target]


def build_httpx_command(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    output_file: Optional[Path] = None,
    json_output: bool = False,
    csv_output: bool = False,
    title: bool = False,
    status_code: bool = False,
    tech_detect: bool = False,
    web_server: bool = False,
    follow_redirects: bool = False,
    content_length: bool = False,
    response_time: bool = False,
    timeout: Optional[int] = None,
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    headers: Optional[str] = None,
    method: Optional[str] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    filter_code: Optional[str] = None,
    filter_length: Optional[str] = None,
    match_code: Optional[str] = None,
    match_length: Optional[str] = None,
    silent: bool = False,
    no_color: bool = True,
    extra_args: Optional[Sequence[str]] = None,
    tool_path: Optional[str] = None,
) -> List[str]:
    path = tool_path or get_executable_path("httpx") or "httpx"
    cmd = [path]
    cmd.extend(_httpx_target_args(path, target, target_list))

    _append_bool(cmd, "-title", title)
    _append_bool(cmd, "-status-code", status_code)
    _append_bool(cmd, "-tech-detect", tech_detect)
    _append_bool(cmd, "-server", web_server)
    _append_bool(cmd, "-follow-redirects", follow_redirects)
    _append_bool(cmd, "-content-length", content_length)
    _append_bool(cmd, "-response-time", response_time)
    _append_pair(cmd, "-timeout", timeout)
    _append_pair(cmd, "-threads", threads)
    _append_pair(cmd, "-rate-limit", rate_limit)
    _append_pair(cmd, "-method", method)
    _append_pair(cmd, "-http-proxy", proxy)
    _append_pair(cmd, "-filter-code", filter_code)
    _append_pair(cmd, "-filter-length", filter_length)
    _append_pair(cmd, "-match-code", match_code)
    _append_pair(cmd, "-match-length", match_length)

    if user_agent:
        cmd.extend(["-H", f"User-Agent: {user_agent}"])
    if headers:
        for header in headers.split(","):
            header = header.strip()
            if header:
                cmd.extend(["-H", header])

    if output_file:
        cmd.extend(["-o", str(output_file)])
    _append_bool(cmd, "-json", json_output)
    _append_bool(cmd, "-csv", csv_output)
    _append_bool(cmd, "-silent", silent)
    _append_bool(cmd, "-no-color", no_color)

    if extra_args:
        cmd.extend([str(arg) for arg in extra_args if str(arg)])
    return cmd


def build_nuclei_command(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    templates: Optional[str] = None,
    template_path: Optional[str] = None,
    tags: Optional[str] = None,
    severity: Optional[str] = None,
    exclude_tags: Optional[str] = None,
    exclude_templates: Optional[str] = None,
    exclude_matchers: Optional[str] = None,
    output_file: Optional[Path] = None,
    jsonl: bool = False,
    csv_output: bool = False,
    silent: bool = False,
    store_resp: bool = False,
    store_resp_dir: Optional[str] = None,
    headers: Optional[str] = None,
    variables: Optional[str] = None,
    rate_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    concurrency: Optional[int] = None,
    bulk_size: Optional[int] = None,
    proxy: Optional[str] = None,
    disable_redirects: bool = False,
    max_redirects: Optional[int] = None,
    user_agent: Optional[str] = None,
    no_interactsh: bool = False,
    interactsh_server: Optional[str] = None,
    interactsh_token: Optional[str] = None,
    markdown_export: Optional[str] = None,
    sarif_export: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
    tool_path: Optional[str] = None,
) -> List[str]:
    path = tool_path or get_executable_path("nuclei") or "nuclei"
    cmd = [path]

    if target_list:
        cmd.extend(["-l", target_list])
    elif target:
        cmd.extend(["-u", target])
    else:
        raise ValueError("nuclei requires target or target_list")

    selected_templates = templates or template_path
    _append_pair(cmd, "-t", selected_templates)
    _append_pair(cmd, "-tags", tags)
    _append_pair(cmd, "-s", severity)
    _append_pair(cmd, "-et", exclude_tags)
    _append_pair(cmd, "-exclude-templates", exclude_templates)
    _append_pair(cmd, "-exclude-matchers", exclude_matchers)
    _append_pair(cmd, "-rl", rate_limit)
    _append_pair(cmd, "-timeout", timeout)
    _append_pair(cmd, "-retries", retries)
    _append_pair(cmd, "-c", concurrency)
    _append_pair(cmd, "-bs", bulk_size)
    _append_pair(cmd, "-proxy", proxy)
    _append_pair(cmd, "-maxr", max_redirects)
    _append_pair(cmd, "-user-agent", user_agent)
    _append_pair(cmd, "-interactsh-server", interactsh_server)
    _append_pair(cmd, "-interactsh-token", interactsh_token)
    _append_pair(cmd, "-markdown-export", markdown_export)
    _append_pair(cmd, "-sarif-export", sarif_export)

    if headers:
        for header in headers.split(","):
            header = header.strip()
            if header:
                cmd.extend(["-H", header])
    _append_pair(cmd, "-var", variables)
    _append_bool(cmd, "-dr", disable_redirects)
    _append_bool(cmd, "-ni", no_interactsh)
    _append_bool(cmd, "-store-resp", store_resp)
    _append_pair(cmd, "-store-resp-dir", store_resp_dir)

    if output_file:
        cmd.extend(["-o", str(output_file)])
    _append_bool(cmd, "-jsonl", jsonl)
    _append_bool(cmd, "-csv", csv_output)
    _append_bool(cmd, "-silent", silent)

    if extra_args:
        cmd.extend([str(arg) for arg in extra_args if str(arg)])
    return cmd


def _stop_process(process: subprocess.Popen, kill: bool = False) -> None:
    """Stop a scanner process and its children on Linux."""
    if process.poll() is not None:
        return

    try:
        if is_linux():
            sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
            sig = sigkill if kill else signal.SIGTERM
            killpg = getattr(os, "killpg")
            killpg(process.pid, sig)
        elif kill:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        return
    except Exception:
        if kill:
            process.kill()
        else:
            process.terminate()


def run_command(
    tool: str,
    command: Sequence[str],
    timeout: Optional[int] = None,
    output_file: Optional[Path] = None,
    dry_run: bool = False,
    on_line: Optional[Callable[[str], None]] = None,
) -> ToolResult:
    cmd = [str(part) for part in command]
    if dry_run:
        line = f"[DRY-RUN] {' '.join(cmd)}"
        if on_line:
            on_line(line)
        else:
            print(line)
        return ToolResult(tool=tool, command=cmd, success=True, output_file=output_file, dry_run=True)

    output_lines: List[str] = []
    timed_out = False
    process: Optional[subprocess.Popen] = None
    timer: Optional[threading.Timer] = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            start_new_session=is_linux(),
        )

        def kill_on_timeout() -> None:
            nonlocal timed_out
            if process is None:
                return
            if process.poll() is None:
                timed_out = True
                _stop_process(process, kill=True)

        timer = threading.Timer(timeout, kill_on_timeout) if timeout else None
        if timer:
            timer.daemon = True
            timer.start()

        if process.stdout:
            for raw_line in process.stdout:
                line = raw_line.rstrip()
                if line:
                    output_lines.append(line)
                    if on_line:
                        on_line(line)
                    else:
                        print(line)

        returncode = process.wait()
        if timer:
            timer.cancel()
        if process.stdout:
            process.stdout.close()
        if timed_out:
            return ToolResult(
                tool=tool,
                command=cmd,
                success=False,
                returncode=returncode,
                output_lines=output_lines,
                output_file=output_file,
                error=f"timed out after {timeout} seconds",
            )
        return ToolResult(
            tool=tool,
            command=cmd,
            success=returncode == 0,
            returncode=returncode,
            output_lines=output_lines,
            output_file=output_file,
            error=None if returncode == 0 else f"exit code {returncode}",
        )
    except KeyboardInterrupt:
        if timer:
            timer.cancel()
        if process is not None:
            _stop_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _stop_process(process, kill=True)
        raise
    except Exception as exc:
        if timer:
            timer.cancel()
        if process is not None:
            _stop_process(process, kill=True)
        return ToolResult(
            tool=tool,
            command=cmd,
            success=False,
            output_lines=output_lines,
            output_file=output_file,
            error=str(exc),
        )


def _read_nonempty_lines(path: Optional[Path]) -> List[str]:
    if not path or not path.exists():
        return []
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    except OSError:
        return []


def _first_token_lines(lines: Iterable[str], prefixes: Tuple[str, ...]) -> List[str]:
    values: List[str] = []
    for line in lines:
        first = line.split()[0]
        if first.startswith(prefixes):
            values.append(first)
    return values


def _extract_naabu_targets(lines: Iterable[str]) -> List[str]:
    targets: List[str] = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if text.startswith("{"):
            try:
                data = json.loads(text)
                host = data.get("host") or data.get("ip")
                port = data.get("port")
                if host and port:
                    targets.append(f"{host}:{port}")
                    continue
            except json.JSONDecodeError:
                pass
        targets.append(text.split()[0])
    return targets


def _extract_http_urls(lines: Iterable[str]) -> List[str]:
    urls: List[str] = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if text.startswith("{"):
            try:
                data = json.loads(text)
                url = data.get("url") or data.get("input")
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    urls.append(url)
                    continue
            except json.JSONDecodeError:
                pass
        first = text.split()[0]
        if first.startswith(("http://", "https://")):
            urls.append(first)
    return urls


def _write_lines(path: Path, lines: Iterable[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _markdown_cell(value: object) -> str:
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value if item)
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def _split_references(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _normalize_finding(data: Dict[str, object]) -> Dict[str, object]:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    info_dict = info if isinstance(info, dict) else {}
    classification = info_dict.get("classification") if isinstance(info_dict.get("classification"), dict) else {}
    classification_dict = classification if isinstance(classification, dict) else {}

    remediation = (
        info_dict.get("remediation")
        or info_dict.get("fix")
        or "Validate the finding, patch or reconfigure the affected service, and remove unnecessary exposure."
    )
    references = _split_references(info_dict.get("reference") or data.get("reference"))
    cve = classification_dict.get("cve-id") or classification_dict.get("cve")

    return {
        "name": info_dict.get("name") or data.get("template-id") or "Unknown finding",
        "severity": str(info_dict.get("severity") or data.get("severity") or "unknown").lower(),
        "template_id": data.get("template-id") or data.get("template_id") or "N/A",
        "matched_at": data.get("matched-at") or data.get("matched") or data.get("host") or data.get("url") or "N/A",
        "description": info_dict.get("description") or "No description provided by the scanner output.",
        "remediation": remediation,
        "references": references,
        "cve": cve,
        "tags": _split_references(info_dict.get("tags")),
    }


def parse_nuclei_findings(path: Optional[Path]) -> List[Dict[str, object]]:
    """Parse nuclei JSONL, CSV, or default text output into normalized findings."""
    if not path or not path.exists():
        return []

    findings: List[Dict[str, object]] = []
    if path.suffix.lower() == ".csv":
        try:
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                for row in csv.DictReader(handle):
                    findings.append(
                        {
                            "name": row.get("name") or row.get("template-id") or "Unknown finding",
                            "severity": (row.get("severity") or "unknown").lower(),
                            "template_id": row.get("template-id") or row.get("template_id") or "N/A",
                            "matched_at": row.get("matched-at") or row.get("host") or row.get("url") or "N/A",
                            "description": row.get("description") or "No description provided by the scanner output.",
                            "remediation": row.get("remediation") or "Validate the finding, patch or reconfigure the affected service, and remove unnecessary exposure.",
                            "references": _split_references(row.get("reference")),
                            "cve": row.get("cve-id") or row.get("cve"),
                            "tags": _split_references(row.get("tags")),
                        }
                    )
            return findings
        except OSError:
            return []

    text_pattern = re.compile(r"^\[(?P<template>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<matched>\S+)")
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith("{"):
                try:
                    data = json.loads(text)
                    if isinstance(data, dict):
                        findings.append(_normalize_finding(data))
                        continue
                except json.JSONDecodeError:
                    pass
            match = text_pattern.match(text)
            if match:
                findings.append(
                    {
                        "name": match.group("template"),
                        "severity": match.group("severity").lower(),
                        "template_id": match.group("template"),
                        "matched_at": match.group("matched"),
                        "description": "Text output did not include a full description. Re-run with --json-output for richer details.",
                        "remediation": "Validate the finding, patch or reconfigure the affected service, and remove unnecessary exposure.",
                        "references": [],
                        "cve": None,
                        "tags": [],
                    }
                )
    except OSError:
        return []
    return findings


def _severity_counts(findings: Sequence[Dict[str, object]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def write_security_findings_report(output_dir: Path, target: str, results: Sequence[ToolResult]) -> Path:
    nuclei_output = next((result.output_file for result in results if result.tool == "nuclei" and result.output_file), None)
    findings = parse_nuclei_findings(nuclei_output)
    counts = _severity_counts(findings)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_findings = sorted(findings, key=lambda item: severity_rank.get(str(item.get("severity")), 5))

    report = output_dir / "security_findings_report.md"
    lines = [
        "# Security Findings and Remediation",
        "",
        f"Target: {target}",
        f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Summary",
        "",
        f"- Total findings: {len(findings)}",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        f"- Informational/Unknown: {counts['info'] + counts['unknown']}",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "No nuclei vulnerability findings were parsed from the saved output.",
                "",
                "If you expected findings, re-run the scan with `--json-output` so the report can include template descriptions, references, and remediation text.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## Findings",
                "",
                "| Severity | Finding | Template | Affected Target | CVE |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in sorted_findings:
            lines.append(
                "| {severity} | {name} | {template} | {matched} | {cve} |".format(
                    severity=_markdown_cell(finding.get("severity")).upper(),
                    name=_markdown_cell(finding.get("name")),
                    template=_markdown_cell(finding.get("template_id")),
                    matched=_markdown_cell(finding.get("matched_at")),
                    cve=_markdown_cell(finding.get("cve") or "N/A"),
                )
            )

        lines.extend(["", "## Remediation Details", ""])
        for index, finding in enumerate(sorted_findings, 1):
            raw_references = finding.get("references")
            references = cast(List[object], raw_references) if isinstance(raw_references, list) else []
            lines.extend(
                [
                    f"### {index}. {_markdown_cell(finding.get('name'))}",
                    "",
                    f"- Severity: {_markdown_cell(finding.get('severity')).upper()}",
                    f"- Template: {_markdown_cell(finding.get('template_id'))}",
                    f"- Affected target: {_markdown_cell(finding.get('matched_at'))}",
                    f"- Description: {_markdown_cell(finding.get('description'))}",
                    f"- Recommended fix: {_markdown_cell(finding.get('remediation'))}",
                ]
            )
            if references:
                lines.append("- References: " + ", ".join(_markdown_cell(ref) for ref in references[:5]))
            lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")
    return report


def write_summary(output_dir: Path, target: str, results: Sequence[ToolResult]) -> Path:
    report = output_dir / "comprehensive_scan_report.txt"
    findings_report = write_security_findings_report(output_dir, target, results)
    lines = [
        "MTScan Comprehensive Scan Report",
        "=" * 80,
        f"Target: {target}",
        f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')}",
        "",
        "Tool Results",
        "-" * 80,
    ]
    lines.append(f"Security findings report: {findings_report}")
    lines.append("")
    for result in results:
        status = "SUCCESS" if result.success else "FAILED"
        lines.append(f"{result.tool}: {status}")
        lines.append(f"Command: {' '.join(result.command)}")
        if result.output_file:
            lines.append(f"Output file: {result.output_file}")
        if result.error:
            lines.append(f"Error: {result.error}")
        lines.append("")
    report.write_text("\n".join(lines), encoding="utf-8")
    return report


def target_urls_for_nuclei(target: str) -> List[str]:
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"http://{target}", f"https://{target}"]


def run_tool(
    tool: str,
    target: str,
    output_dir: Optional[Path] = None,
    save_output: bool = False,
    json_output: bool = False,
    dry_run: bool = False,
    on_line: Optional[Callable[[str], None]] = None,
    **options,
) -> ToolResult:
    output_path: Optional[Path] = None
    if save_output:
        output_dir = output_dir or default_output_dir(target)
        if not dry_run:
            output_dir = ensure_output_dir(output_dir)
        csv_output = bool(options.get(f"{tool}_csv"))
        output_path = output_path_for(tool, output_dir, json_output or bool(options.get(f"{tool}_json")), csv_output)

    if tool == "naabu":
        cmd = build_naabu_command(
            target=target,
            ports=options.get("ports"),
            top_ports=options.get("top_ports"),
            exclude_ports=options.get("exclude_ports"),
            threads=options.get("threads"),
            rate=options.get("rate"),
            timeout=options.get("naabu_timeout"),
            retries=options.get("naabu_retries"),
            scan_type=options.get("scan_type"),
            output_file=output_path,
            json_output=json_output or bool(options.get("naabu_json")),
            csv_output=bool(options.get("naabu_csv")),
            silent=bool(options.get("tool_silent")),
        )
    elif tool == "httpx":
        cmd = build_httpx_command(
            target=target,
            output_file=output_path,
            json_output=json_output or bool(options.get("httpx_json")),
            csv_output=bool(options.get("httpx_csv")),
            title=bool(options.get("title")),
            status_code=bool(options.get("status_code")),
            tech_detect=bool(options.get("tech_detect")),
            web_server=bool(options.get("web_server")),
            follow_redirects=bool(options.get("follow_redirects")),
            content_length=bool(options.get("content_length")),
            response_time=bool(options.get("response_time")),
            timeout=options.get("httpx_timeout"),
            threads=options.get("httpx_threads"),
            rate_limit=options.get("rate_limit"),
            headers=options.get("headers"),
            method=options.get("method"),
            user_agent=options.get("user_agent"),
            proxy=options.get("proxy"),
            filter_code=options.get("filter_code"),
            filter_length=options.get("filter_length"),
            match_code=options.get("match_code"),
            match_length=options.get("match_length"),
            silent=bool(options.get("tool_silent")),
        )
    elif tool == "nuclei":
        nuclei_target = target if target.startswith(("http://", "https://")) else f"http://{target}"
        cmd = build_nuclei_command(
            target=nuclei_target,
            templates=options.get("templates"),
            template_path=options.get("template_path"),
            tags=options.get("tags"),
            severity=options.get("severity"),
            exclude_tags=options.get("exclude_tags"),
            exclude_templates=options.get("exclude_templates"),
            exclude_matchers=options.get("exclude_matchers"),
            output_file=output_path,
            jsonl=json_output or bool(options.get("nuclei_json")),
            csv_output=bool(options.get("nuclei_csv")),
            silent=bool(options.get("tool_silent")),
            store_resp=bool(options.get("store_resp")),
            store_resp_dir=options.get("store_resp_dir"),
            headers=options.get("custom_headers") or options.get("headers"),
            variables=options.get("vars"),
            rate_limit=options.get("nuclei_rate_limit"),
            timeout=options.get("nuclei_timeout"),
            retries=options.get("nuclei_retries"),
            concurrency=options.get("concurrency"),
            bulk_size=options.get("parallel_processing"),
            proxy=options.get("proxy"),
            disable_redirects=bool(options.get("disable_redirects")),
            max_redirects=options.get("max_redirects"),
            user_agent=options.get("nuclei_user_agent"),
            no_interactsh=bool(options.get("no_interactsh")),
            interactsh_server=options.get("interactsh_server"),
            interactsh_token=options.get("interactsh_token"),
            markdown_export=options.get("markdown_export"),
            sarif_export=options.get("sarif_export"),
        )
    else:
        raise ValueError(f"unknown tool: {tool}")

    return run_command(tool, cmd, timeout=options.get("timeout"), output_file=output_path, dry_run=dry_run, on_line=on_line)


def run_chain(
    target: str,
    output_dir: Optional[Path] = None,
    save_output: bool = True,
    json_output: bool = False,
    dry_run: bool = False,
    on_line: Optional[Callable[[str], None]] = None,
    **options,
) -> List[ToolResult]:
    output_dir = output_dir or default_output_dir(target)
    if not dry_run:
        output_dir = ensure_output_dir(output_dir)
    results: List[ToolResult] = []

    naabu_json = json_output or bool(options.get("naabu_json"))
    naabu_file = output_path_for("naabu", output_dir, naabu_json, bool(options.get("naabu_csv")))
    naabu_cmd = build_naabu_command(
        target=target,
        ports=options.get("ports"),
        top_ports=options.get("top_ports"),
        exclude_ports=options.get("exclude_ports"),
        threads=options.get("threads"),
        rate=options.get("rate"),
        timeout=options.get("naabu_timeout"),
        retries=options.get("naabu_retries"),
        scan_type=options.get("scan_type"),
        output_file=naabu_file if save_output else None,
        json_output=naabu_json,
        csv_output=bool(options.get("naabu_csv")),
        silent=bool(options.get("tool_silent")),
    )
    naabu_result = run_command(
        "naabu",
        naabu_cmd,
        timeout=options.get("timeout"),
        output_file=naabu_file if save_output else None,
        dry_run=dry_run,
        on_line=on_line,
    )
    results.append(naabu_result)

    naabu_lines = [] if dry_run else (_read_nonempty_lines(naabu_file) or naabu_result.output_lines)
    httpx_input = output_dir / "httpx_targets.txt"
    if naabu_lines:
        _write_lines(httpx_input, _extract_naabu_targets(naabu_lines))
        httpx_target_list = str(httpx_input)
        httpx_target = None
    else:
        httpx_target_list = None
        httpx_target = target

    httpx_json = json_output or bool(options.get("httpx_json"))
    httpx_file = output_path_for("httpx", output_dir, httpx_json, bool(options.get("httpx_csv")))
    httpx_cmd = build_httpx_command(
        target=httpx_target,
        target_list=httpx_target_list,
        output_file=httpx_file if save_output else None,
        json_output=httpx_json,
        csv_output=bool(options.get("httpx_csv")),
        title=bool(options.get("title", True)),
        status_code=bool(options.get("status_code", True)),
        tech_detect=bool(options.get("tech_detect", True)),
        web_server=bool(options.get("web_server", True)),
        follow_redirects=bool(options.get("follow_redirects")),
        content_length=bool(options.get("content_length")),
        response_time=bool(options.get("response_time")),
        timeout=options.get("httpx_timeout"),
        threads=options.get("httpx_threads"),
        rate_limit=options.get("rate_limit"),
        headers=options.get("headers"),
        method=options.get("method"),
        user_agent=options.get("user_agent"),
        proxy=options.get("proxy"),
        silent=bool(options.get("tool_silent")),
    )
    httpx_result = run_command(
        "httpx",
        httpx_cmd,
        timeout=options.get("timeout"),
        output_file=httpx_file if save_output else None,
        dry_run=dry_run,
        on_line=on_line,
    )
    results.append(httpx_result)

    httpx_lines = [] if dry_run else (_read_nonempty_lines(httpx_file) or httpx_result.output_lines)
    urls = _extract_http_urls(httpx_lines)
    if not urls:
        urls = target_urls_for_nuclei(target)
    nuclei_targets = output_dir / "nuclei_targets.txt"
    if not dry_run:
        _write_lines(nuclei_targets, urls)

    nuclei_json = json_output or bool(options.get("nuclei_json"))
    nuclei_file = output_path_for("nuclei", output_dir, nuclei_json, bool(options.get("nuclei_csv")))
    nuclei_cmd = build_nuclei_command(
        target_list=str(nuclei_targets),
        templates=options.get("templates"),
        template_path=options.get("template_path"),
        tags=options.get("tags"),
        severity=options.get("severity"),
        exclude_tags=options.get("exclude_tags"),
        exclude_templates=options.get("exclude_templates"),
        exclude_matchers=options.get("exclude_matchers"),
        output_file=nuclei_file if save_output else None,
        jsonl=nuclei_json,
        csv_output=bool(options.get("nuclei_csv")),
        silent=bool(options.get("tool_silent")),
        store_resp=bool(options.get("store_resp")),
        store_resp_dir=options.get("store_resp_dir"),
        headers=options.get("custom_headers") or options.get("headers"),
        variables=options.get("vars"),
        rate_limit=options.get("nuclei_rate_limit"),
        timeout=options.get("nuclei_timeout"),
        retries=options.get("nuclei_retries"),
        concurrency=options.get("concurrency"),
        bulk_size=options.get("parallel_processing"),
        proxy=options.get("proxy"),
        disable_redirects=bool(options.get("disable_redirects")),
        max_redirects=options.get("max_redirects"),
        user_agent=options.get("nuclei_user_agent"),
        no_interactsh=bool(options.get("no_interactsh")),
        interactsh_server=options.get("interactsh_server"),
        interactsh_token=options.get("interactsh_token"),
        markdown_export=options.get("markdown_export"),
        sarif_export=options.get("sarif_export"),
    )
    results.append(run_command("nuclei", nuclei_cmd, timeout=options.get("timeout"), output_file=nuclei_file if save_output else None, dry_run=dry_run, on_line=on_line))

    if not dry_run:
        write_summary(output_dir, target, results)
    return results


def print_line(line: str) -> None:
    print(line)
    sys.stdout.flush()
