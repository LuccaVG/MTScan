"""Runtime policies shared by MTScan entry points.

These guards keep the existing runner API stable while enforcing two behaviors:
URL targets are reduced to a hostname only when passed to Naabu, and completed
raw scanner outputs are retained as evidence while transient chain handoff lists
are removed.
"""

from __future__ import annotations

import functools
import urllib.parse
from pathlib import Path
from types import ModuleType
from typing import Optional


def naabu_target(target: Optional[str]) -> Optional[str]:
    """Return a Naabu-compatible host/IP while leaving non-URL targets unchanged."""
    if not target or not target.startswith(("http://", "https://")):
        return target

    parsed = urllib.parse.urlparse(target)
    if not parsed.hostname:
        raise ValueError("URL targets must include a host.")
    return parsed.hostname


def apply_tool_runner_fixes(tool_runner: ModuleType) -> None:
    """Apply stable target/evidence policies to the loaded tool runner once."""
    if getattr(tool_runner, "_runtime_guards_applied", False):
        return

    original_build_naabu_command = tool_runner.build_naabu_command

    @functools.wraps(original_build_naabu_command)
    def build_naabu_command(*args, **kwargs):
        if args:
            args = (naabu_target(args[0]),) + args[1:]
        elif "target" in kwargs:
            kwargs["target"] = naabu_target(kwargs.get("target"))
        return original_build_naabu_command(*args, **kwargs)

    def cleanup_intermediate_outputs(output_dir: Path) -> None:
        """Delete only transient target handoff lists, not scanner evidence."""
        for path in (output_dir / "httpx_targets.txt", output_dir / "nuclei_targets.txt"):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue

    def keep_output_file_references(_results) -> None:
        """Retain ToolResult.output_file references after report generation."""
        return None

    tool_runner.build_naabu_command = build_naabu_command
    tool_runner.cleanup_intermediate_outputs = cleanup_intermediate_outputs
    tool_runner._clear_result_output_files = keep_output_file_references
    tool_runner._runtime_guards_applied = True
