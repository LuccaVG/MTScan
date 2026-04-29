import os
import sys
import socket
import platform
import subprocess
import shutil
import time
import json
import shlex
from pathlib import Path
from typing import List, Dict, Any, Union, Optional, Tuple

# Constants for reuse across modules
DEFAULT_TIMEOUT = 300
DEFAULT_RETRY = 1
SECURITY_TOOLS = ["naabu", "httpx", "nuclei"]

def run_cmd(cmd: Union[str, List[str]], shell: bool = False, check: bool = False, use_sudo: bool = False, timeout: int = DEFAULT_TIMEOUT, retry: int = DEFAULT_RETRY, silent: bool = False) -> bool:
    """Enhanced command runner with real-time output for security tools."""
    if shell:
        raise ValueError("shell=True is not supported; pass commands as an argument list")

    if isinstance(cmd, list):
        cmd_str = ' '.join(cmd)
        run_args = cmd
    else:
        cmd_str = cmd
        run_args = shlex.split(cmd)
        
    for attempt in range(retry + 1):
        try:
            if not silent:
                print(f"Running: {cmd_str}")
            
            # Handle sudo and Windows special case in a platform-independent way
            if use_sudo and platform.system().lower() != "windows":
                try:
                    # os.geteuid() is only available on Unix-like systems
                    if hasattr(os, 'geteuid') and os.geteuid() != 0: # type: ignore
                        if isinstance(cmd, list):
                            run_args = ["sudo"] + run_args
                        else:
                            run_args = ["sudo"] + run_args
                except AttributeError:
                    # We're not on a Unix system, so we can't use sudo
                    pass
            
            # For security tools, we want real-time output, so don't capture stdout/stderr
            # unless explicitly silenced
            if silent:
                # Silent mode - capture all output
                process = subprocess.Popen(
                    run_args,
                    shell=False,
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL, 
                    text=True
                )
            else:
                # Real-time mode - let output pass through to terminal
                process = subprocess.Popen(
                    run_args,
                    shell=False,
                    text=True
                )
            
            # Wait with timeout
            try:
                process.wait(timeout=timeout)
                
                # Check return code
                if process.returncode != 0:
                    # Retry logic
                    if attempt < retry:
                        if not silent:
                            print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                        time.sleep(2 * (attempt + 1))  # Exponential backoff
                        continue
                    
                    if check:
                        raise subprocess.CalledProcessError(process.returncode, run_args)
                    return False
                
                return True
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                if not silent:
                    print(f"Command timed out after {timeout} seconds: {cmd_str}")
                if attempt < retry:
                    if not silent:
                        print(f"Retrying ({attempt+1}/{retry})...")
                    time.sleep(2 * (attempt + 1))
                    continue
                return False
                
        except subprocess.CalledProcessError as e:
            if not silent:
                print(f"Command failed: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2 * (attempt + 1))
                continue
            return False
        except Exception as e:
            if not silent:
                print(f"Error running command {cmd_str}: {str(e)}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2 * (attempt + 1))
                continue
            return False
    
    return False

def check_required_commands(commands: List[str]) -> List[str]:
    """Check if required commands are available and return missing ones."""
    missing = []
    for cmd in commands:
        if not get_executable_path(cmd):
            missing.append(cmd)
    return missing

def safe_read_json(json_file: str, default: Any = None) -> Any:
    """Safely read a JSON file with error handling."""
    if not os.path.exists(json_file):
        return default
    
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Try to read line by line for JSONL format
        try:
            results = []
            with open(json_file, 'r') as f:
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
            if results:
                return results
        except:
            pass
            
        print(f"Warning: Could not parse JSON from {json_file}")
        return default
    except Exception as e:
        print(f"Error reading {json_file}: {e}")
        return default

def safe_write_json(data: Any, json_file: str) -> bool:
    """Safely write data to a JSON file with error handling."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(json_file)), exist_ok=True)
        
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error writing to {json_file}: {e}")
        return False

def check_tools_installation() -> Dict[str, Dict[str, Any]]:
    """Verify if all required security tools are installed and working."""
    tools = {
        "naabu": {"installed": False, "version": None, "command": "naabu -version"},
        "httpx": {"installed": False, "version": None, "command": "httpx -version"},
        "nuclei": {"installed": False, "version": None, "command": "nuclei -version"}
    }
    
    for tool, data in tools.items():
        tool_path = get_executable_path(tool)
        
        if tool_path:
            try:
                result = subprocess.run(data["command"].split(), 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                
                data["installed"] = True
                data["version"] = result.stdout.strip() if result.stdout else "Unknown"
                data["path"] = tool_path
            except Exception as e:
                data["error"] = str(e)
    
    return tools

def check_network() -> bool:
    """Check for network connectivity."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server with timeout
            socket.create_connection((dns, 53), 3)
            return True
        except (socket.timeout, socket.error, OSError):
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

def create_directory_if_not_exists(directory: str) -> bool:
    """Create a directory if it doesn't exist."""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False

def get_executable_path(cmd: str) -> Optional[str]:
    """Find the path to an executable, checking PATH and common locations."""
    try:
        from tool_runner import get_executable_path as shared_get_executable_path
        shared_path = shared_get_executable_path(cmd)
        if shared_path:
            return shared_path
    except Exception:
        try:
            from src.tool_runner import get_executable_path as shared_get_executable_path
            shared_path = shared_get_executable_path(cmd)
            if shared_path:
                return shared_path
        except Exception:
            pass

    # Check in PATH first
    cmd_path = shutil.which(cmd)
    if cmd_path:
        return cmd_path
    
    # Common Go tool installation locations
    possible_locations = [
        f"/usr/local/bin/{cmd}",                         # Exposed scanner binary
        "/usr/local/bin/httpx-toolkit" if cmd == "httpx" else "",
        os.path.expanduser(f"~/go/bin/{cmd}"),           # User's go/bin
        f"/root/go/bin/{cmd}",                           # Root's go/bin (common in Kali)
        f"/usr/local/go/bin/{cmd}",                      # System Go installation
        f"/usr/bin/{cmd}",                               # System package manager
        "/usr/bin/httpx-toolkit" if cmd == "httpx" else "",
        f"/opt/go/bin/{cmd}",                            # Alternative Go location
        os.path.expanduser(f"~/.local/bin/{cmd}"),       # User's local bin
        f"/snap/bin/{cmd}",                              # Snap packages
    ]
    
    for path in possible_locations:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    return None

def get_system_memory_gb() -> float:
    """
    Get the total system memory in GB (Linux only).
    """
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_kb = int(line.split()[1])
                    return mem_kb / (1024 * 1024)
    except Exception as e:
        print(f"Error detecting system memory: {e}")
    return 4.0  # Default to 4GB if detection fails

def normalize_path(path: str) -> str:
    """
    Normalize file paths for Linux systems.
    """
    return path.replace('\\', '/')

# Add utility for ensuring proper file permissions 
def ensure_executable(file_path: str) -> bool:
    """Make sure a file is executable (Linux only)."""
    try:
        os.chmod(file_path, 0o700)
        return True
    except Exception as e:
        print(f"Error making {file_path} executable: {e}")
        return False

def verify_linux_platform() -> bool:
    """Verify that the script is running on a Linux platform."""
    import platform
    if platform.system().lower() != "linux":
        print("This toolkit is designed EXCLUSIVELY for Linux systems.")
        print("Supported: Debian, Kali Linux, Ubuntu, Arch Linux")
        print("NOT Supported: Windows, macOS, WSL")
        return False
    return True
