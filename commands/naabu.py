#!/usr/bin/env python3
"""Naabu wrapper used by MTScan."""

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


def run_naabu(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    ports: Optional[str] = None,
    exclude_ports: Optional[str] = None,
    threads: Optional[int] = None,
    rate: Optional[int] = None,
    timeout: Optional[int] = None,
    json_output: bool = False,
    output_file: Optional[str] = None,
    save_output: bool = False,
    tool_silent: bool = False,
    additional_args: Optional[list] = None,
    auto_install: bool = False,
) -> bool:
    if not check_naabu():
        if auto_install and auto_install_naabu():
            pass
        else:
            print("Naabu is not installed or not available in PATH.")
            return False

    out = Path(output_file) if save_output and output_file else None
    cmd = tool_runner.build_naabu_command(
        target=target,
        target_list=target_list,
        ports=ports,
        exclude_ports=exclude_ports,
        threads=threads,
        rate=rate,
        timeout=timeout,
        output_file=out,
        json_output=json_output,
        silent=tool_silent,
        extra_args=additional_args,
    )
    result = tool_runner.run_command("naabu", cmd, output_file=out)
    return result.success


def parse_naabu_results(output_file: str, json_format: bool = False):
    path = Path(output_file)
    if not path.is_file():
        print(f"Error: Naabu output file '{output_file}' not found.")
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


def check_naabu() -> bool:
    available, path, detail = tool_runner.verify_tool("naabu")
    if available:
        print(f"Naabu is available at {path}")
        return True
    print(f"Naabu unavailable: {detail}")
    return False


def get_naabu_capabilities():
    available, path, detail = tool_runner.verify_tool("naabu")
    return {
        "available": available,
        "installation_path": path,
        "version": detail,
        "scan_types": ["connect", "syn"],
    }


def auto_install_naabu() -> bool:
    print("Installing Naabu using Go...")
    cmd = ["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]
    result = subprocess.run(cmd, check=False)
    return result.returncode == 0 and check_naabu()


def main() -> int:
    parser = argparse.ArgumentParser(description="Naabu wrapper")
    parser.add_argument("-host", "--target", help="Target host")
    parser.add_argument("-l", "--list", dest="target_list", help="Target list file")
    parser.add_argument("-p", "--ports", help="Ports to scan")
    parser.add_argument("--exclude-ports", help="Ports to exclude")
    parser.add_argument("--threads", type=int)
    parser.add_argument("--rate", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("-o", "--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()

    if args.install:
        return 0 if auto_install_naabu() else 1

    ok = run_naabu(
        target=args.target,
        target_list=args.target_list,
        ports=args.ports,
        exclude_ports=args.exclude_ports,
        threads=args.threads,
        rate=args.rate,
        timeout=args.timeout,
        json_output=args.json,
        output_file=args.output,
        save_output=bool(args.output),
        tool_silent=args.silent,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
