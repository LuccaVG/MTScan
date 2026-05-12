#!/usr/bin/env python3
"""
MTScan command-line workflow.

Runs naabu, httpx, nuclei individually or as a chained scan.  The actual tool
discovery and command construction live in tool_runner.py so the CLI, menu,
and wrappers all share the same behavior.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src import scan_storage
    from src import tool_runner
else:
    from . import scan_storage
    from . import tool_runner


def signal_handler(sig, frame):
    print("\nWARNING: Scan interrupted by user. Partial results may be available.")
    sys.exit(130)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", nargs="?", help="Target to scan (IP, domain, or URL)")
    parser.add_argument("-host", "--host", help="Target host to scan")

    parser.add_argument("-naabu", "--naabu", action="store_true", help="Run naabu port scanner")
    parser.add_argument("-httpx", "--httpx", action="store_true", help="Run httpx service detection")
    parser.add_argument("-nuclei", "--nuclei", action="store_true", help="Run nuclei vulnerability scanner")
    parser.add_argument("--all", "--chain", dest="all_tools", action="store_true", help="Run naabu, httpx, and nuclei in sequence")

    parser.add_argument("-p", "--ports", help="Ports to scan with naabu")
    parser.add_argument("--top-ports", help="Number of top ports to scan with naabu")
    parser.add_argument("--threads", type=int, help="Number of naabu threads")
    parser.add_argument("--rate", type=int, help="Naabu packet rate")
    parser.add_argument("--exclude-ports", help="Ports to exclude from naabu")
    parser.add_argument("--scan-type", choices=["syn", "connect"], help="Naabu scan type")
    parser.add_argument("--naabu-timeout", type=int, help="Naabu timeout")
    parser.add_argument("--naabu-retries", type=int, help="Naabu retries")
    parser.add_argument("--source-port", type=int, help="Accepted for compatibility")
    parser.add_argument("--interface", help="Accepted for compatibility")
    parser.add_argument("--host-discovery", action="store_true", help="Accepted for compatibility")
    parser.add_argument("--ping", action="store_true", help="Accepted for compatibility")
    parser.add_argument("--no-ping", action="store_true", help="Accepted for compatibility")
    parser.add_argument("--naabu-debug", action="store_true", help="Accepted for compatibility")
    parser.add_argument("--naabu-json", action="store_true", help="Naabu JSON output")
    parser.add_argument("--naabu-csv", action="store_true", help="Naabu CSV output")

    parser.add_argument("--title", action="store_true", help="Extract HTTP titles")
    parser.add_argument("--status-code", action="store_true", help="Show HTTP status codes")
    parser.add_argument("--tech-detect", action="store_true", help="Detect HTTP technologies")
    parser.add_argument("--web-server", action="store_true", help="Show web server header")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--rate-limit", type=int, help="HTTPX rate limit")
    parser.add_argument("--headers", help="Custom HTTP headers, comma separated")
    parser.add_argument("--content-length", action="store_true", help="Show content length")
    parser.add_argument("--response-time", action="store_true", help="Show response time")
    parser.add_argument("--httpx-timeout", type=int, help="HTTPX timeout")
    parser.add_argument("--httpx-threads", type=int, help="HTTPX threads")
    parser.add_argument("--httpx-retries", type=int, help="Accepted for compatibility")
    parser.add_argument("--method", help="HTTP method")
    parser.add_argument("--user-agent", help="Custom HTTP User-Agent")
    parser.add_argument("--filter-code", help="Filter HTTP status codes")
    parser.add_argument("--filter-length", help="Filter response lengths")
    parser.add_argument("--match-code", help="Match HTTP status codes")
    parser.add_argument("--match-length", help="Match response lengths")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--httpx-json", action="store_true", help="HTTPX JSON output")
    parser.add_argument("--httpx-csv", action="store_true", help="HTTPX CSV output")

    parser.add_argument("-t", "--templates", help="Nuclei templates")
    parser.add_argument("--template-path", help="Nuclei template path")
    parser.add_argument("--tags", help="Nuclei template tags")
    parser.add_argument("--severity", help="Nuclei severity filter")
    parser.add_argument("--exclude-tags", help="Nuclei excluded tags")
    parser.add_argument("--exclude-templates", help="Nuclei excluded templates")
    parser.add_argument("--exclude-severity", help="Accepted for compatibility")
    parser.add_argument("--exclude-matchers", help="Nuclei excluded matchers")
    parser.add_argument("--concurrency", type=int, help="Nuclei concurrency")
    parser.add_argument("--parallel-processing", type=int, help="Nuclei bulk size")
    parser.add_argument("--nuclei-rate-limit", type=int, help="Nuclei rate limit")
    parser.add_argument("--nuclei-timeout", type=int, help="Nuclei timeout")
    parser.add_argument("--nuclei-retries", type=int, help="Nuclei retries")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--disable-redirects", action="store_true", help="Disable redirects")
    parser.add_argument("--max-redirects", type=int, help="Maximum redirects")
    parser.add_argument("--nuclei-user-agent", help="Nuclei User-Agent")
    parser.add_argument("--custom-headers", help="Nuclei headers, comma separated")
    parser.add_argument("--vars", help="Nuclei variables")
    parser.add_argument("--store-resp", action="store_true", help="Store Nuclei responses")
    parser.add_argument("--store-resp-dir", help="Directory for Nuclei responses")
    parser.add_argument("--interactsh-server", help="Interactsh server")
    parser.add_argument("--no-interactsh", action="store_true", help="Disable Interactsh")
    parser.add_argument("--interactsh-token", help="Interactsh token")
    parser.add_argument("--include-rr", action="store_true", help="Accepted for compatibility")
    parser.add_argument("--nuclei-json", action="store_true", help="Nuclei JSONL output")
    parser.add_argument("--nuclei-csv", action="store_true", help="Nuclei CSV output")
    parser.add_argument("--markdown-export", help="Nuclei Markdown export directory")
    parser.add_argument("--sarif-export", help="Nuclei SARIF export file")

    parser.add_argument("--tool-silent", action="store_true", help="Ask tools to show only essential output")
    parser.add_argument("--verbose", action="store_true", help="Accepted for compatibility")
    parser.add_argument("-s", "--stealth", action="store_true", help="Use lower-rate settings")
    parser.add_argument("-o", "--output-dir", help="Directory for output files")
    parser.add_argument("--save-output", action="store_true", help="Save tool output to files")
    parser.add_argument("--json-output", action="store_true", help="Save JSON/JSONL output where supported")
    parser.add_argument("--update-templates", action="store_true", help="Update nuclei templates before scanning")
    parser.add_argument("--timeout", type=int, help="Per-tool timeout in seconds")
    parser.add_argument("--force-tools", action="store_true", help="Continue even when tool checks fail")
    parser.add_argument("--skip-network-check", action="store_true", help="Skip network connectivity check")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing tools")
    parser.add_argument("--check-tools", action="store_true", help="Check scanner tool availability and exit")


def selected_tools(args: argparse.Namespace) -> List[str]:
    if args.all_tools:
        return ["naabu", "httpx", "nuclei"]

    tools = []
    if args.naabu:
        tools.append("naabu")
    if args.httpx:
        tools.append("httpx")
    if args.nuclei:
        tools.append("nuclei")
    return tools


def args_to_options(args: argparse.Namespace) -> Dict[str, Any]:
    options = vars(args).copy()
    for reserved in (
        "target",
        "host",
        "naabu",
        "httpx",
        "nuclei",
        "all_tools",
        "output_dir",
        "save_output",
        "json_output",
        "dry_run",
        "skip_network_check",
        "force_tools",
        "update_templates",
        "check_tools",
    ):
        options.pop(reserved, None)

    if args.stealth:
        if options.get("rate") is None:
            options["rate"] = 10
        if options.get("threads") is None:
            options["threads"] = 25
        if options.get("scan_type") is None:
            options["scan_type"] = "connect"
        if options.get("nuclei_rate_limit") is None:
            options["nuclei_rate_limit"] = 5
        if options.get("concurrency") is None:
            options["concurrency"] = 5
        if options.get("parallel_processing") is None:
            options["parallel_processing"] = 5
        options["no_interactsh"] = True

    if args.all_tools:
        options["title"] = True
        options["status_code"] = True
        options["tech_detect"] = True
        options["web_server"] = True

    return options


def check_platform(args: argparse.Namespace) -> None:
    if args.dry_run:
        return
    if not tool_runner.is_linux():
        print("This toolkit executes scans on Linux only.")
        print("Run it from a native Linux VM or host.")
        sys.exit(1)


def check_network(args: argparse.Namespace) -> None:
    if args.dry_run or args.skip_network_check:
        return
    print("Checking network connectivity...")
    if tool_runner.check_network_connectivity():
        print("Network connectivity: OK")
        return
    response = input("Network connectivity check failed. Continue anyway? [y/N]: ")
    if response.strip().lower() not in ("y", "yes"):
        print("Scan cancelled.")
        sys.exit(1)


def update_templates(args: argparse.Namespace) -> None:
    if not args.update_templates:
        return
    path = tool_runner.get_executable_path("nuclei") or "nuclei"
    cmd = [path, "-update-templates"]
    if args.dry_run:
        print(f"[DRY-RUN] {' '.join(cmd)}")
        return
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0 and not args.force_tools:
        print("Template update failed.")
        sys.exit(result.returncode)


def check_tools(tools: List[str], args: argparse.Namespace) -> bool:
    if args.dry_run:
        return True

    missing = []
    print("Checking tool availability...")
    for tool in tools:
        available, path, detail = tool_runner.verify_tool(tool)
        if available:
            print(f"{tool}: Available at {path}")
        else:
            print(f"{tool}: Not available ({detail})")
            missing.append(tool)

    if missing and not args.force_tools:
        print(f"Missing tools: {', '.join(missing)}")
        print("Install missing tools or pass --force-tools to continue.")
        sys.exit(1)

    return not missing


def result_record(result: tool_runner.ToolResult) -> Dict[str, object]:
    return {
        "tool": result.tool,
        "command_preview": tool_runner.redact_command(result.command),
        "success": result.success,
        "returncode": result.returncode,
        "error": result.error,
        "output_file": str(result.output_file) if result.output_file else None,
        "output_lines": len(result.output_lines),
        "dry_run": result.dry_run,
    }


def persist_cli_scan(
    target: str,
    mode: str,
    output_dir: Path,
    results: List[tool_runner.ToolResult],
    args: argparse.Namespace,
) -> None:
    if args.dry_run:
        return
    report = output_dir / tool_runner.REPORT_FILENAME
    summary = tool_runner.summarize_scan_results(target, results)
    if report.exists():
        summary["report_file"] = report.name
    now = _dt.datetime.now().isoformat(timespec="seconds")
    record = {
        "id": uuid.uuid4().hex[:12],
        "target": target,
        "mode": mode,
        "status": "completed" if all(result.success for result in results) else "failed",
        "created_at": now,
        "started_at": now,
        "finished_at": now,
        "dry_run": False,
        "json_output": bool(args.json_output),
        "output_dir": str(output_dir),
        "error": None if all(result.success for result in results) else "One or more tools failed.",
        "results": [result_record(result) for result in results],
        "summary": summary,
        "report_file": report.name if report.exists() else None,
    }
    try:
        scan_storage.create_store().save_scan(record)  # type: ignore[attr-defined]
    except Exception as exc:
        print(f"Storage warning: {exc}")


def run(args: argparse.Namespace) -> int:
    target = args.host or args.target
    if not target:
        print("No target specified. Use -host or provide a positional target.")
        return 1

    tools = selected_tools(args)
    if not tools:
        print("No tool selected. Use -naabu, -httpx, -nuclei, or --all.")
        return 1

    options = args_to_options(args)
    try:
        target = tool_runner.validate_scan_request(target, options)
    except tool_runner.ScanInputError as exc:
        print(f"Invalid scan request: {exc}")
        return 2

    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    if args.save_output or args.all_tools:
        output_dir = output_dir or tool_runner.default_output_dir(target)
        if not args.dry_run:
            output_dir = tool_runner.ensure_output_dir(output_dir)

    print(f"Target: {target}")
    print(f"Tools: {', '.join(tools)}")
    print(f"Report output: {'yes' if args.save_output or args.all_tools else 'no'}")
    if output_dir:
        print(f"Output directory: {output_dir}")

    if args.all_tools or tools == ["naabu", "httpx", "nuclei"]:
        results = tool_runner.run_chain(
            target,
            output_dir=output_dir,
            save_output=True,
            json_output=args.json_output,
            dry_run=args.dry_run,
            **options,
        )
        report = output_dir / tool_runner.REPORT_FILENAME if output_dir else None
        if report and not args.dry_run:
            print(f"Report: {report}")
            persist_cli_scan(target, "chain", output_dir, results, args)
        return 0 if all(result.success for result in results) else 1

    results = []
    for tool in tools:
        result = tool_runner.run_tool(
            tool,
            target,
            output_dir=output_dir,
            save_output=args.save_output,
            json_output=args.json_output,
            dry_run=args.dry_run,
            **options,
        )
        results.append(result)
        status = "OK" if result.success else "FAILED"
        print(f"{tool}: {status}")
        if result.error:
            print(f"{tool} error: {result.error}")

    if output_dir and args.save_output and not args.dry_run:
        report = tool_runner.write_summary(output_dir, target, results)
        print(f"Report: {report}")
        persist_cli_scan(target, tools[0] if len(tools) == 1 else "chain", output_dir, results, args)

    return 0 if all(result.success for result in results) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="MTScan vulnerability scanning workflow")
    add_arguments(parser)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    check_platform(args)

    if args.check_tools:
        ok = check_tools(list(tool_runner.SECURITY_TOOLS), args)
        sys.exit(0 if ok else 1)

    check_network(args)
    update_templates(args)

    tools = selected_tools(args)
    check_tools(tools, args)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
