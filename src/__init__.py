"""MTScan package initialization."""

from . import tool_runner as tool_runner
from .runtime_guards import apply_tool_runner_fixes

apply_tool_runner_fixes(tool_runner)

__all__ = ["tool_runner"]
