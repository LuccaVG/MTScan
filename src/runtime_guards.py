"""Runtime hardening policies shared by MTScan entry points.

These guards keep the public runner API stable while enforcing target validation,
URL-to-Naabu normalization, current ProjectDiscovery CLI compatibility, safe
profile behavior, defensive command redaction, and evidence retention.
"""

from __future__ import annotations

import functools
import inspect
import ipaddress
import re
import urllib.parse
from pathlib import Path
from types import ModuleType
from typing import Optional


HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
IPV4_LIKE_PATTERN = re.compile(r"^\d+(?:\.\d+){3}$")
URL_USERINFO_PATTERN = re.compile(r"(?i)(https?://)[^/@\s]+@")

RESTRICTIVE_PROFILE_SIGNATURES = {
    ("exposure,misconfig", "critical,high,medium", 75, 10),
    ("exposure,misconfig,panel", "critical,high", 100, 8),
    ("exposure,misconfig", "critical,high,medium", 5, 5),
}


def _scan_error(tool_runner: ModuleType, message: str) -> Exception:
    error_type = getattr(tool_runner, "ScanInputError", ValueError)
    return error_type(message)


def _validate_hostname(tool_runner: ModuleType, host: str) -> None:
    value = host.rstrip(".")
    if not value or len(value) > 253:
        raise _scan_error(tool_runner, "Target hostname is invalid.")

    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass

    if IPV4_LIKE_PATTERN.fullmatch(value):
        raise _scan_error(tool_runner, "Target IP address is invalid.")

    labels = value.split(".")
    if any(not label or not HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise _scan_error(tool_runner, "Target hostname is invalid.")


def _validate_port(tool_runner: ModuleType, value: object, label: str = "port") -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        raise _scan_error(tool_runner, f"{label.capitalize()} must be a number.")
    if port < 1 or port > 65535:
        raise _scan_error(tool_runner, f"{label.capitalize()} must be between 1 and 65535.")
    return port


def validate_target(tool_runner: ModuleType, target: object) -> str:
    """Validate supported target forms without accepting credential-bearing URLs."""
    value = str(target or "").strip()
    if not value:
        raise _scan_error(tool_runner, "Target is required.")
    if len(value) > 2048:
        raise _scan_error(tool_runner, "Target is too long.")
    if tool_runner.TARGET_FORBIDDEN_PATTERN.search(value):
        raise _scan_error(tool_runner, "Target cannot contain whitespace or control characters.")

    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise _scan_error(tool_runner, "Only http and https URLs are supported for URL targets.")
        if not parsed.netloc or not parsed.hostname:
            raise _scan_error(tool_runner, "URL targets must include a host.")
        if "\\" in parsed.netloc:
            raise _scan_error(tool_runner, "URL host contains an invalid character.")
        if parsed.username is not None or parsed.password is not None:
            raise _scan_error(tool_runner, "Credentials are not allowed in scan target URLs.")
        try:
            port = parsed.port
        except ValueError:
            raise _scan_error(tool_runner, "URL port must be between 1 and 65535.")
        if port is not None:
            _validate_port(tool_runner, port, "URL port")
        _validate_hostname(tool_runner, parsed.hostname)
        return value

    if not tool_runner.BARE_TARGET_PATTERN.fullmatch(value):
        raise _scan_error(tool_runner, "Target must be an IP, CIDR range, hostname, host:port, or http(s) URL.")

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise _scan_error(tool_runner, "CIDR targets must contain a valid IPv4 or IPv6 network.")
        return value

    if value.startswith("["):
        match = re.fullmatch(r"\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?", value)
        if not match:
            raise _scan_error(tool_runner, "Bracketed IPv6 targets must use [address] or [address]:port syntax.")
        try:
            parsed_ip = ipaddress.ip_address(match.group("host"))
        except ValueError:
            raise _scan_error(tool_runner, "Target IPv6 address is invalid.")
        if parsed_ip.version != 6:
            raise _scan_error(tool_runner, "Bracket syntax is only supported for IPv6 targets.")
        if match.group("port") is not None:
            _validate_port(tool_runner, match.group("port"))
        return value

    if value.count(":") > 1:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise _scan_error(tool_runner, "Target IPv6 address is invalid.")
        return value

    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        if not host or not port_text.isdigit():
            raise _scan_error(tool_runner, "Host ports must use host:port with a numeric port.")
        _validate_hostname(tool_runner, host)
        _validate_port(tool_runner, port_text)
        return value

    _validate_hostname(tool_runner, value)
    return value


def naabu_target(target: Optional[str]) -> Optional[str]:
    if not target or not target.startswith(("http://", "https://")):
        return target

    parsed = urllib.parse.urlparse(target)
    if not parsed.hostname:
        raise ValueError("URL targets must include a host.")
    return parsed.hostname


def _redact_url_userinfo(value: str) -> str:
    return URL_USERINFO_PATTERN.sub(r"\1[redacted]@", value)


def _profile_tags_are_restrictive(kwargs: dict) -> bool:
    try:
        signature = (
            str(kwargs.get("tags") or ""),
            str(kwargs.get("severity") or ""),
            int(kwargs.get("rate_limit") or 0),
            int(kwargs.get("concurrency") or 0),
        )
    except (TypeError, ValueError):
        return False
    return signature in RESTRICTIVE_PROFILE_SIGNATURES


def _bound_arguments(function, args, kwargs) -> dict:
    try:
        return dict(inspect.signature(function).bind_partial(*args, **kwargs).arguments)
    except (TypeError, ValueError):
        return dict(kwargs)


def _replace_paired_flag(command: list[str], old_flag: str, new_flag: str, value: object) -> None:
    if value in (None, ""):
        return
    expected = str(value)
    for index in range(len(command) - 1):
        if command[index] == old_flag and command[index + 1] == expected:
            command[index] = new_flag
            return


def _option_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def apply_tool_runner_fixes(tool_runner: ModuleType) -> None:
    if getattr(tool_runner, "_runtime_guards_applied", False):
        return

    original_validate_scan_options = tool_runner.validate_scan_options
    original_build_naabu_command = tool_runner.build_naabu_command
    original_build_httpx_command = tool_runner.build_httpx_command
    original_build_nuclei_command = tool_runner.build_nuclei_command
    original_redact_command = tool_runner.redact_command

    @functools.wraps(original_validate_scan_options)
    def validate_scan_options(options):
        if _option_enabled(options.get("nuclei_csv")):
            raise _scan_error(
                tool_runner,
                "Current ProjectDiscovery Nuclei does not support CSV output; use JSONL output instead.",
            )
        return original_validate_scan_options(options)

    @functools.wraps(original_build_naabu_command)
    def build_naabu_command(*args, **kwargs):
        if args:
            args = (naabu_target(args[0]),) + args[1:]
        elif "target" in kwargs:
            kwargs["target"] = naabu_target(kwargs.get("target"))
        return original_build_naabu_command(*args, **kwargs)

    @functools.wraps(original_build_httpx_command)
    def build_httpx_command(*args, **kwargs):
        bound = _bound_arguments(original_build_httpx_command, args, kwargs)
        command = original_build_httpx_command(*args, **kwargs)
        _replace_paired_flag(command, "-method", "-x", bound.get("method"))
        return command

    @functools.wraps(original_build_nuclei_command)
    def build_nuclei_command(*args, **kwargs):
        if not args and _profile_tags_are_restrictive(kwargs):
            kwargs = dict(kwargs)
            kwargs["tags"] = None

        bound = _bound_arguments(original_build_nuclei_command, args, kwargs)
        if _option_enabled(bound.get("csv_output")):
            raise ValueError(
                "Current ProjectDiscovery Nuclei does not support CSV output; use JSONL output instead."
            )

        command = original_build_nuclei_command(*args, **kwargs)
        _replace_paired_flag(command, "-et", "-etags", bound.get("exclude_tags"))
        _replace_paired_flag(command, "-maxr", "-mr", bound.get("max_redirects"))

        user_agent = bound.get("user_agent")
        if user_agent not in (None, ""):
            expected = str(user_agent)
            for index in range(len(command) - 1):
                if command[index] == "-user-agent" and command[index + 1] == expected:
                    command[index] = "-H"
                    command[index + 1] = f"User-Agent: {expected}"
                    break
        return command

    @functools.wraps(original_redact_command)
    def redact_command(command):
        return [_redact_url_userinfo(value) for value in original_redact_command(command)]

    def cleanup_intermediate_outputs(output_dir: Path) -> None:
        for path in (output_dir / "httpx_targets.txt", output_dir / "nuclei_targets.txt"):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue

    def keep_output_file_references(_results) -> None:
        return None

    tool_runner.validate_target = functools.partial(validate_target, tool_runner)
    tool_runner.validate_scan_options = validate_scan_options
    tool_runner.build_naabu_command = build_naabu_command
    tool_runner.build_httpx_command = build_httpx_command
    tool_runner.build_nuclei_command = build_nuclei_command
    tool_runner.redact_command = redact_command
    tool_runner.cleanup_intermediate_outputs = cleanup_intermediate_outputs
    tool_runner._clear_result_output_files = keep_output_file_references
    tool_runner._runtime_guards_applied = True
