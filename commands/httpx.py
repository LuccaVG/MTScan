#!/usr/bin/env python3
"""HTTPX wrapper used by MTScan."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import tool_runner


def run_httpx(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    output_file: Optional[str] = None,
    json_output: bool = False,
    title: bool = False,
    status_code: bool = False,
    tech_detect: bool = False,
    web_server: bool = False,
    follow_redirects: bool = False,
    save_output: bool = False,
    tool_silent: bool = False,
    timeout: Optional[int] = None,
    threads: Optional[int] = None,
    additional_args: Optional[list] = None,
    auto_install: bool = False,
) -> bool:
    if not check_httpx():
        if auto_install and auto_install_httpx():
            pass
        else:
            print("HTTPX is not installed or not available in PATH.")
            return False

    out = Path(output_file) if save_output and output_file else None
    cmd = tool_runner.build_httpx_command(
        target=target,
        target_list=target_list,
        output_file=out,
        json_output=json_output,
        title=title,
        status_code=status_code,
        tech_detect=tech_detect,
        web_server=web_server,
        follow_redirects=follow_redirects,
        silent=tool_silent,
        timeout=timeout,
        threads=threads,
        extra_args=additional_args,
    )
    result = tool_runner.run_command("httpx", cmd, output_file=out)
    return result.success


def parse_httpx_results(output_file: str, json_format: bool = False):
    path = Path(output_file)
    if not path.is_file():
        print(f"Error: HTTPX output file '{output_file}' not found.")
        return None

    if not json_format:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]

    results = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def check_httpx() -> bool:
    available, path, detail = tool_runner.verify_tool("httpx")
    if available:
        print(f"HTTPX is available at {path}")
        return True
    print(f"HTTPX unavailable: {detail}")
    return False


def auto_install_httpx() -> bool:
    print("Installing HTTPX using Go...")
    cmd = ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"]
    result = subprocess.run(cmd, check=False)
    return result.returncode == 0 and check_httpx()


def get_httpx_version():
    available, _path, detail = tool_runner.verify_tool("httpx")
    return detail if available else None


def get_httpx_capabilities():
    available, path, detail = tool_runner.verify_tool("httpx")
    return {
        "available": available,
        "version": detail,
        "installation_path": path,
        "features": ["HTTP probing", "status codes", "titles", "technology detection", "JSON output"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTPX wrapper")
    parser.add_argument("target", nargs="?")
    parser.add_argument("-l", "--list", dest="target_list")
    parser.add_argument("-o", "--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--title", action="store_true")
    parser.add_argument("--status-code", action="store_true")
    parser.add_argument("--tech-detect", action="store_true")
    parser.add_argument("--web-server", action="store_true")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--threads", type=int)
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()

    if args.install:
        return 0 if auto_install_httpx() else 1

    ok = run_httpx(
        target=args.target,
        target_list=args.target_list,
        output_file=args.output,
        json_output=args.json,
        title=args.title,
        status_code=args.status_code,
        tech_detect=args.tech_detect,
        web_server=args.web_server,
        follow_redirects=args.follow_redirects,
        save_output=bool(args.output),
        tool_silent=args.silent,
        timeout=args.timeout,
        threads=args.threads,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
