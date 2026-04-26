"""
commands package - Wrappers for security tools

This package contains Python wrappers for the security tools used by the toolkit:
- naabu: Port scanner
- httpx: HTTP service discovery
- nuclei: Vulnerability scanner
"""

__all__ = ["naabu", "httpx", "nuclei"]

# Import tool modules if they exist
try:
    from . import naabu, httpx, nuclei
except ImportError as e:
    # Tools might not be installed yet
    import sys
    print(f"Warning: Could not import security tool wrappers ({str(e)})")
    print("Make sure you've run install/setup.py to install all required components.")
