#!/usr/bin/env python3
"""Nuclei wrapper used by MTScan."""

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


def run_nuclei(
    target: Optional[str] = None,
    target_list: Optional[str] = None,
    templates: Optional[str] = None,
    tags: Optional[str] = None,
    severity: Optional[str] = None,
    output_file: Optional[str] = None,
    jsonl: bool = False,
    save_output: bool = False,
    tool_silent: bool = False,
    store_resp: bool = False,
    headers: Optional[str] = None,
    variables: Optional[str] = None,
    rate_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    additional_args: Optional[list] = None,
    auto_install: bool = False,
) -> bool:
    if not check_nuclei():
        if auto_install and install_nuclei():
            pass
        else:
            print("Nuclei is not installed or not available in PATH.")
            return False

    out = Path(output_file) if save_output and output_file else None
    cmd = tool_runner.build_nuclei_command(
        target=target,
        target_list=target_list,
        templates=templates,
        tags=tags,
        severity=severity,
        output_file=out,
        jsonl=jsonl,
        silent=tool_silent,
        store_resp=store_resp,
        headers=headers,
        variables=variables,
        rate_limit=rate_limit,
        timeout=timeout,
        extra_args=additional_args,
    )
    result = tool_runner.run_command("nuclei", cmd, timeout=timeout or None, output_file=out)
    return result.success


def parse_nuclei_results(output_file: str, json_format: bool = False):
    path = Path(output_file)
    if not path.is_file():
        print(f"Error: Nuclei output file '{output_file}' not found.")
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


def install_nuclei() -> bool:
    print("Installing nuclei using Go...")
    cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]
    result = subprocess.run(cmd, check=False)
    return result.returncode == 0 and check_nuclei()


def nuclei_update_templates() -> bool:
    path = tool_runner.get_executable_path("nuclei")
    if not path:
        print("Error: Nuclei is not installed")
        return False
    result = tool_runner.run_command("nuclei", [path, "-update-templates"])
    return result.success


def get_nuclei_version():
    available, _path, detail = tool_runner.verify_tool("nuclei")
    return detail if available else None


def list_nuclei_templates(tags: Optional[str] = None, severity: Optional[str] = None) -> bool:
    path = tool_runner.get_executable_path("nuclei")
    if not path:
        print("Error: Nuclei is not installed")
        return False
    cmd = [path, "-tl"]
    if tags:
        cmd.extend(["-tags", tags])
    if severity:
        cmd.extend(["-s", severity])
    return tool_runner.run_command("nuclei", cmd).success


def check_nuclei() -> bool:
    available, path, detail = tool_runner.verify_tool("nuclei")
    if available:
        print(f"Nuclei is available at {path}")
        return True
    print(f"Nuclei unavailable: {detail}")
    return False


def get_nuclei_capabilities():
    available, path, detail = tool_runner.verify_tool("nuclei")
    return {
        "available": available,
        "version": detail,
        "installation_path": path,
        "templates_updated": (Path.home() / "nuclei-templates").exists(),
    }


def update_nuclei_templates() -> bool:
    return nuclei_update_templates()


def quick_nuclei_scan(target: str, output_file: Optional[str] = None, severity: str = "medium,high,critical", save_output: bool = False):
    return run_nuclei(
        target=target,
        severity=severity,
        output_file=output_file,
        jsonl=bool(output_file),
        save_output=save_output,
        tool_silent=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Nuclei wrapper")
    parser.add_argument("-u", "--target")
    parser.add_argument("-l", "--list", dest="target_list")
    parser.add_argument("-t", "--templates")
    parser.add_argument("--tags")
    parser.add_argument("-s", "--severity")
    parser.add_argument("-o", "--output")
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument("--save-output", action="store_true")
    parser.add_argument("--tool-silent", action="store_true")
    parser.add_argument("--store-resp", action="store_true")
    parser.add_argument("--headers")
    parser.add_argument("--vars")
    parser.add_argument("--rate-limit", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()

    if args.install:
        return 0 if install_nuclei() else 1
    if args.update:
        return 0 if nuclei_update_templates() else 1
    if args.version:
        version = get_nuclei_version()
        print(version or "Nuclei not found")
        return 0 if version else 1

    ok = run_nuclei(
        target=args.target,
        target_list=args.target_list,
        templates=args.templates,
        tags=args.tags,
        severity=args.severity,
        output_file=args.output,
        jsonl=args.jsonl,
        save_output=args.save_output or bool(args.output),
        tool_silent=args.tool_silent,
        store_resp=args.store_resp,
        headers=args.headers,
        variables=args.vars,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
