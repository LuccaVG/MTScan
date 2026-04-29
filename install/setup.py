#!/usr/bin/env python3
"""
Linux Vulnerability Analysis Toolkit - Master Installation Script
================================================================================

This is the MAIN installer, setup, and configuration script for the Linux-only
Vulnerability Analysis Toolkit. It handles everything:

- Linux platform verification and distribution detection  
- Root permission enforcement
- System package management and updates
- Dependency installation and verification
- Go environment setup
- Security tools installation (naabu, httpx, nuclei)
- Python dependencies and virtual environment
- Configuration optimization
- Complete system verification

Usage: sudo python3 install/setup.py

Requirements:
- Linux operating system (Debian/Ubuntu/Kali/Arch)
- Root privileges (sudo)
- Internet connection
- Python 3.8+

================================================================================
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import time
import ctypes
import urllib.request
import signal
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Union, cast

SignalValue = Union[int, signal.Signals]
KillpgFunction = Callable[[int, SignalValue], None]
_killpg = getattr(os, "killpg", None)
LINUX_KILLPG = cast(Optional[KillpgFunction], _killpg if callable(_killpg) else None)
SIGKILL: SignalValue = getattr(signal, "SIGKILL", signal.SIGTERM)

# ANSI Color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Linux distribution configurations
SUPPORTED_DISTROS = {
    'debian': {
        'name': 'Debian',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc']
    },
    'kali': {
        'name': 'Kali Linux',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc'],
        'special_repos': True
    },
    'ubuntu': {
        'name': 'Ubuntu',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'software-properties-common', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc']
    },
    'arch': {
        'name': 'Arch Linux',
        'package_manager': 'pacman',
        'install_cmd': ['pacman', '-S', '--noconfirm'],
        'update_cmd': ['pacman', '-Sy'],
        'packages': ['curl', 'wget', 'git', 'base-devel', 'python-pip', 'go', 'unzip', 'ca-certificates', 'libpcap', 'pkgconfig', 'gcc']
    }
}

HTTPX_BINARY_NAMES = ["httpx-toolkit", "httpx"]


def binary_names_for_tool(tool: str) -> List[str]:
    return HTTPX_BINARY_NAMES if tool == "httpx" else [tool]


def tool_responds(path: str, tool: str) -> bool:
    """Return True when a scanner binary responds to a normal version/help probe."""
    for flag in ("-version", "--version"):
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                return True
        except Exception:
            continue

    for flag in ("-h", "--help"):
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = f"{result.stdout}\n{result.stderr}".lower()
            if result.returncode == 0:
                if tool != "httpx":
                    return True
                if any(marker in output for marker in ("projectdiscovery", "fast and multi-purpose", "-tech-detect", "-status-code")):
                    return True
        except Exception:
            continue
    return False


def find_scanner_binary(tool: str) -> Optional[str]:
    """Find the usable scanner binary, handling Kali's httpx-toolkit name."""
    candidates: List[str] = []
    for name in binary_names_for_tool(tool):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    candidate_dirs = [
        "/usr/local/bin",
        "/root/go/bin",
        os.path.expanduser("~/go/bin"),
        "/usr/bin",
        "/snap/bin",
    ]
    for directory in candidate_dirs:
        for name in binary_names_for_tool(tool):
            candidates.append(os.path.join(directory, name))

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and tool_responds(candidate, tool):
            return candidate
    return None


def expose_tool_to_path(tool: str, source_path: str) -> bool:
    """Make a root-installed Go tool available to regular shells via /usr/local/bin."""
    target_name = "httpx-toolkit" if tool == "httpx" else tool
    target_path = os.path.join("/usr/local/bin", target_name)
    try:
        if os.path.abspath(source_path) == os.path.abspath(target_path):
            return True
        if os.path.lexists(target_path):
            os.remove(target_path)
        os.symlink(source_path, target_path)
        return True
    except OSError:
        try:
            shutil.copy2(source_path, target_path)
            os.chmod(target_path, 0o755)
            return True
        except OSError as exc:
            print(f"{Colors.YELLOW}  Could not expose {tool} at /usr/local/bin: {exc}{Colors.END}")
            return False

def print_header():
    """Print installation header."""
    print(f"{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.WHITE}Linux Vulnerability Analysis Toolkit - Master Installer{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Single-point installer for complete toolkit setup{Colors.END}")
    print(f"{Colors.YELLOW}Platform: Linux-Only | Requires: Root/Sudo access{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

def detect_linux_distro() -> Optional[str]:
    """Detect the Linux distribution with enhanced detection."""
    try:
        # Try reading /etc/os-release first (most reliable)
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if content:  # Ensure content is not None or empty
                    content = content.lower()
                    if 'kali' in content:
                        return 'kali'
                    elif 'arch' in content:
                        return 'arch'
                    elif 'ubuntu' in content:
                        return 'ubuntu'
                    elif 'debian' in content:
                        return 'debian'
        
        # Check /etc/debian_version for Debian-based systems
        if os.path.exists('/etc/debian_version'):
            if os.path.exists('/etc/lsb-release'):
                with open('/etc/lsb-release', 'r') as f:
                    lsb_content = f.read()
                    if lsb_content and 'ubuntu' in lsb_content.lower():
                        return 'ubuntu'
            return 'debian'
        
        # Fallback to package manager detection
        if shutil.which('pacman'):
            return 'arch'
        elif shutil.which('apt') or shutil.which('apt-get'):
            return 'debian'
            
    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not detect distribution: {e}{Colors.END}")
    
    return None

def ensure_linux_only() -> bool:
    """Ensure the system is Linux-only and reject other platforms."""
    if platform.system().lower() != "linux":
        print(f"{Colors.RED}╔═════════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.RED}║                               ERROR                             ║{Colors.END}")
        print(f"{Colors.RED}║                                                                 ║{Colors.END}")
        print(f"{Colors.RED}║     This toolkit is designed EXCLUSIVELY for Linux systems      ║{Colors.END}")
        print(f"{Colors.RED}║                                                                 ║{Colors.END}")
        print(f"{Colors.RED}║           Supported: Debian, Kali, Ubuntu, Arch Linux           ║{Colors.END}")
        print(f"{Colors.RED}║           NOT Supported: Windows, macOS, WSL (limited)          ║{Colors.END}")
        print(f"{Colors.RED}║                                                                 ║{Colors.END}")
        print(f"{Colors.RED}║          Please use a native Linux environment for optimal      ║{Colors.END}")
        print(f"{Colors.RED}║             security tool performance and compatibility.        ║{Colors.END}")
        print(f"{Colors.RED}╚═════════════════════════════════════════════════════════════════╝{Colors.END}")
        return False
    return True

def check_root_permissions() -> bool:
    """Check for root/sudo permissions."""
    try:
        # Method 1: Check effective user ID (Linux/Unix only)
        try:
            # On Windows, ctypes.CDLL(None) fails, so we need to check platform first
            if platform.system().lower() == "linux":
                euid = ctypes.CDLL(None).geteuid()
                if euid == 0:
                    print(f"{Colors.GREEN} Running with root privileges{Colors.END}")
                    return True
            else:
                print(f"{Colors.YELLOW}  Not on Linux - skipping root user ID check{Colors.END}")
        except (OSError, AttributeError) as e:
            # Not on a Unix-like system or geteuid not available
            print(f"{Colors.YELLOW}  Cannot check effective user ID: {e}{Colors.END}")
          # Method 2: Check sudo access
        print(f"{Colors.YELLOW}  Not running as root. Checking sudo access...{Colors.END}")
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, check=False)
            if result.returncode == 0:
                print(f"{Colors.GREEN} Sudo access confirmed{Colors.END}")
                return True
            else:
                print(f"{Colors.RED} This script requires root privileges or sudo access{Colors.END}")
                print(f"{Colors.WHITE}Please run: sudo python3 install/setup.py{Colors.END}")
                return False
        except FileNotFoundError:
            print(f"{Colors.RED} 'sudo' command not found. This script requires sudo access on Linux{Colors.END}")
            print(f"{Colors.WHITE}Please ensure you're running on a Linux system with sudo installed{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED} Error checking permissions: {e}{Colors.END}")
        print(f"{Colors.WHITE}Please ensure you have root/sudo access{Colors.END}")
        return False

def check_internet_connectivity() -> bool:
    """Check internet connectivity using multiple methods without emojis."""
    import socket
    print(f"{Colors.WHITE}Checking internet connectivity...{Colors.END}")
    
    # Method 1: DNS resolution test
    dns_hosts = ["www.google.com", "github.com", "cloudflare.com"]
    for host in dns_hosts:
        try:
            socket.gethostbyname(host)
            print(f"{Colors.GREEN}   DNS resolution to {host}: SUCCESS{Colors.END}")
            return True
        except socket.gaierror:
            print(f"{Colors.YELLOW}   DNS resolution to {host}: FAILED{Colors.END}")
            continue
    
    # Method 2: Direct socket connection to DNS servers
    dns_servers = [
        ("8.8.8.8", 53),      # Google DNS
        ("1.1.1.1", 53),      # Cloudflare DNS
        ("9.9.9.9", 53)       # Quad9 DNS
    ]
    
    for dns_host, dns_port in dns_servers:
        try:
            with socket.create_connection((dns_host, dns_port), timeout=5) as sock:
                print(f"{Colors.GREEN}   Connection to {dns_host}:{dns_port}: SUCCESS{Colors.END}")
                return True
        except (socket.timeout, socket.error, OSError):
            print(f"{Colors.YELLOW}   Connection to {dns_host}:{dns_port}: FAILED{Colors.END}")
            continue
    
    # Method 3: Ping test
    ping_targets = ["8.8.8.8", "1.1.1.1"]
    for target in ping_targets:
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "3", "-q", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10
            )
            if result.returncode == 0:
                print(f"{Colors.GREEN}   Ping to {target}: SUCCESS{Colors.END}")
                return True
            else:
                print(f"{Colors.YELLOW}   Ping to {target}: FAILED{Colors.END}")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            print(f"{Colors.YELLOW}   Ping to {target}: ERROR{Colors.END}")
            continue
    
    # Method 4: HTTP connectivity test
    http_urls = ["https://www.google.com", "https://github.com"]
    for url in http_urls:
        try:
            urllib.request.urlopen(url, timeout=10)
            print(f"{Colors.GREEN}   HTTP connectivity to {url}: SUCCESS{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.YELLOW}   HTTP connectivity to {url}: FAILED{Colors.END}")
            continue
    
    # All methods failed
    print(f"{Colors.RED}   All connectivity tests failed{Colors.END}")
    print(f"{Colors.WHITE}Troubleshooting suggestions:{Colors.END}")
    print(f"{Colors.WHITE}  - Check physical network connection{Colors.END}")
    print(f"{Colors.WHITE}  - Verify DNS settings{Colors.END}")
    print(f"{Colors.WHITE}  - Check firewall/proxy settings{Colors.END}")
    print(f"{Colors.WHITE}  - Test: ping 8.8.8.8{Colors.END}")
    print(f"{Colors.WHITE}  - Test: nslookup google.com{Colors.END}")
    return False

def validate_system_requirements() -> Tuple[bool, Optional[str]]:
    """Validate all system requirements."""
    
    # Check Linux platform
    if not ensure_linux_only():
        return False, None
    
    # Detect distribution
    distro = detect_linux_distro()
    if not distro or distro not in SUPPORTED_DISTROS:
        print(f"{Colors.RED} Could not detect supported Linux distribution{Colors.END}")
        print(f"{Colors.WHITE}Supported: Debian, Ubuntu, Kali Linux, Arch Linux{Colors.END}")
        return False, None
    
    print(f"{Colors.GREEN} Detected: {SUPPORTED_DISTROS[distro]['name']}{Colors.END}")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print(f"{Colors.RED} Python 3.8+ required. Current: {sys.version}{Colors.END}")
        return False, None
    print(f"{Colors.GREEN} Python version: {sys.version.split()[0]}{Colors.END}")
      # Check internet connectivity
    if not check_internet_connectivity():
        print(f"{Colors.RED} Internet connectivity required for installation{Colors.END}")
        print(f"{Colors.WHITE}Please check your network connection and try again{Colors.END}")
        return False, None
    
    return True, distro

def stop_process_tree(process: subprocess.Popen) -> None:
    """Terminate a process and its children so timeout retries cannot hang."""
    if process.poll() is not None:
        return

    try:
        if platform.system().lower() == "linux" and LINUX_KILLPG is not None:
            LINUX_KILLPG(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if platform.system().lower() == "linux" and LINUX_KILLPG is not None:
                LINUX_KILLPG(process.pid, SIGKILL)
            else:
                process.kill()
            process.wait(timeout=5)
        except Exception:
            pass
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def run_timed_command(
    cmd: List[str],
    timeout_seconds: int,
    env: Optional[Dict[str, str]] = None,
    capture_stdout: bool = True,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str, bool]:
    """Run a command with process-group timeout protection."""
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        start_new_session=platform.system().lower() == "linux",
    )

    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode or 0, stdout or "", stderr or "", False
    except subprocess.TimeoutExpired:
        stop_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except Exception:
            stdout, stderr = "", ""
        return process.returncode if process.returncode is not None else -9, stdout or "", stderr or "", True


def run_with_timeout(cmd: List[str], timeout_seconds: int = 300, description: str = "", allow_warnings: bool = True, env_override: Optional[Dict[str, str]] = None) -> bool:
    """Run command with timeout protection and enhanced progress indication."""
    try:
        print(f"{Colors.WHITE}{description}...{Colors.END}")
        
        # Create environment with non-interactive defaults
        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        env['NEEDRESTART_MODE'] = 'a'  # Prevent needrestart from hanging
        env['UCF_FORCE_CONFOLD'] = '1'  # Use old config files to prevent prompts
        if env_override:
            env.update(env_override)

        stdout, stderr, timed_out = "", "", False
        returncode, stdout, stderr, timed_out = run_timed_command(
            cmd,
            timeout_seconds,
            env=env,
            capture_stdout='Installing' in description,
        )

        if timed_out:
            print(f"{Colors.YELLOW} {description} timed out after {timeout_seconds}s; process tree was stopped{Colors.END}")
            return False
            
        if returncode == 0:
                print(f"{Colors.GREEN} {description} completed successfully{Colors.END}")
                return True
        else:
                # Enhanced error handling for Go tool installations
                if 'go install' in ' '.join(cmd) or any('github.com' in arg for arg in cmd):
                    # For Go installations, any non-zero exit code is a failure
                    print(f"{Colors.RED} {description} failed (exit code: {returncode}){Colors.END}")
                    if stderr:
                        error_msg = stderr.strip()
                        if error_msg:
                            print(f"{Colors.RED}  Error details: {error_msg[:300]}{Colors.END}")
                            
                            # Provide specific guidance for common Go installation errors
                            if 'no such file or directory' in error_msg.lower():
                                print(f"{Colors.YELLOW}   GOBIN directory may not exist or be in PATH{Colors.END}")
                            elif 'permission denied' in error_msg.lower():
                                print(f"{Colors.YELLOW}   Check GOPATH/bin directory permissions{Colors.END}")
                            elif 'connection refused' in error_msg.lower() or 'timeout' in error_msg.lower():
                                print(f"{Colors.YELLOW}   Network connectivity issue - check internet connection{Colors.END}")
                            elif 'pcap.h' in error_msg.lower():
                                print(f"{Colors.YELLOW}   Missing libpcap-dev package for naabu compilation{Colors.END}")
                    return False
                elif allow_warnings:
                    # For package operations, warnings may be acceptable
                    print(f"{Colors.YELLOW} {description} completed with warnings (exit code: {returncode}){Colors.END}")
                    if stderr:
                        error_msg = stderr.strip()
                        if error_msg and "error" in error_msg.lower():
                            print(f"{Colors.YELLOW}  Warning: {error_msg[:200]}{Colors.END}")
                    return True  # Continue on warnings for most package operations
                else:
                    print(f"{Colors.RED} {description} failed (exit code: {returncode}){Colors.END}")
                    if stderr:
                        error_msg = stderr.strip()
                        if error_msg:
                            print(f"{Colors.RED}  Error: {error_msg[:200]}{Colors.END}")
                    return False
            
    except Exception as e:
        print(f"{Colors.RED} {description} failed: {e}{Colors.END}")
        return False

def fix_package_locks() -> bool:
    """Fix common package manager lock issues with enhanced safety and longer timeouts."""
    print(f"{Colors.WHITE}Checking and fixing package locks...{Colors.END}")
    
    # Kill any hanging processes with more aggressive approach
    try:
        # Kill specific hanging processes
        subprocess.run(['pkill', '-9', '-f', 'apt'], capture_output=True, timeout=10)
        subprocess.run(['pkill', '-9', '-f', 'dpkg'], capture_output=True, timeout=10)
        subprocess.run(['pkill', '-9', '-f', 'unattended-upgrade'], capture_output=True, timeout=10)
        subprocess.run(['pkill', '-9', '-f', 'needrestart'], capture_output=True, timeout=10)
        time.sleep(3)  # Wait longer for processes to terminate
    except:
        pass
    
    lock_files = [
        '/var/lib/dpkg/lock',
        '/var/lib/dpkg/lock-frontend', 
        '/var/cache/apt/archives/lock',
        '/var/lib/apt/lists/lock'
    ]
    
    locks_removed = 0
    for lock_file in lock_files:
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
                locks_removed += 1
            except:
                pass
    
    if locks_removed > 0:
        print(f"{Colors.GREEN} Removed {locks_removed} package locks{Colors.END}")
        # Fix broken packages with extended timeouts
        run_with_timeout(['dpkg', '--configure', '-a'], 240, "Configuring packages (extended timeout)")
        run_with_timeout(['apt', '--fix-broken', 'install', '-y'], 360, "Fixing broken packages (extended timeout)")
    
    return True

def fix_kali_repositories() -> bool:
    """Fix Kali Linux repository issues by updating sources."""
    try:
        print(f"{Colors.WHITE}Fixing Kali Linux repositories...{Colors.END}")
        
        # Backup current sources
        subprocess.run(['cp', '/etc/apt/sources.list', '/etc/apt/sources.list.backup'], 
                      capture_output=True)
        
        # Add reliable Kali mirrors
        kali_sources = """
# Official Kali repositories
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib

# Additional mirrors for redundancy
deb http://mirror.truenetwork.ru/kali kali-rolling main non-free contrib
deb http://kali.download/kali kali-rolling main non-free contrib
"""
        
        with open('/etc/apt/sources.list', 'w') as f:
            f.write(kali_sources)
        
        print(f"{Colors.GREEN} Updated Kali repositories with reliable mirrors{Colors.END}")
        
        # Update package lists with new repositories
        if run_with_timeout(['apt', 'update'], 300, "Updating with fixed repositories"):
            return True
        else:
            # Restore backup if update fails
            subprocess.run(['cp', '/etc/apt/sources.list.backup', '/etc/apt/sources.list'], 
                          capture_output=True)
            return False
            
    except Exception as e:
        print(f"{Colors.YELLOW} Repository fix failed: {e}{Colors.END}")
        return False

def install_libpcap_alternative() -> bool:
    """Install libpcap-dev using alternative methods."""
    try:
        print(f"{Colors.WHITE}Attempting alternative libpcap-dev installation...{Colors.END}")
        
        # Method 1: Try with --fix-missing
        if run_with_timeout(['apt', 'install', 'libpcap-dev', '--fix-missing', '-y'], 180, "Installing libpcap-dev with --fix-missing"):
            return True
        
        # Method 2: Try individual component packages
        libpcap_packages = ['libpcap0.8-dev', 'libpcap-dev']
        for package in libpcap_packages:
            if run_with_timeout(['apt', 'install', package, '-y'], 120, f"Installing {package}"):
                return True
        
        # Method 3: Try downloading and installing manually with correct URLs
        print(f"{Colors.WHITE}Attempting manual libpcap-dev download...{Colors.END}")
        try:
            # Get architecture
            arch_result = subprocess.run(['dpkg', '--print-architecture'], 
                                       capture_output=True, text=True, check=True)
            arch = arch_result.stdout.strip()
            
            # Fixed URLs - pointing to correct libpcap package paths
            mirrors = [
                f"http://http.kali.org/kali/pool/main/libp/libpcap/libpcap-dev_1.10.4-4_all.deb",
                f"http://mirror.truenetwork.ru/kali/pool/main/libp/libpcap/libpcap-dev_1.10.4-4_all.deb",
                f"http://http.kali.org/kali/pool/main/libp/libpcap/libpcap0.8-dev_1.10.4-4_{arch}.deb"
            ]
            
            for mirror in mirrors:
                try:
                    if run_with_timeout(['wget', '-q', mirror, '-O', '/tmp/libpcap-dev.deb'], 60, f"Downloading from {mirror}"):
                        if run_with_timeout(['dpkg', '-i', '/tmp/libpcap-dev.deb'], 60, "Installing downloaded package"):
                            # Install dependencies if needed
                            run_with_timeout(['apt', '--fix-broken', 'install', '-y'], 120, "Fixing dependencies")
                            return True
                except:
                    continue
                    
        except Exception as e:
            print(f"{Colors.YELLOW} Manual download failed: {e}{Colors.END}")
        
        # Method 4: Try installing from universe repository (for Ubuntu/Debian derivatives)
        print(f"{Colors.WHITE}Trying alternative repository sources...{Colors.END}")
        try:
            # Add universe repository if it doesn't exist
            result = subprocess.run(['apt', 'update'], capture_output=True)
            if run_with_timeout(['apt', 'install', 'libpcap-dev', '--install-suggests', '-y'], 180, "Installing with suggests"):
                return True
        except:
            pass
        
        # Method 5: Build from source as last resort
        print(f"{Colors.WHITE}Attempting to build libpcap from source...{Colors.END}")
        try:
            # Install build dependencies first
            build_deps = ['build-essential', 'flex', 'bison']
            for dep in build_deps:
                run_with_timeout(['apt', 'install', dep, '-y'], 120, f"Installing {dep}")
            
            # Download and build libpcap
            if run_with_timeout(['wget', '-q', 'https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz', '-O', '/tmp/libpcap.tar.gz'], 120, "Downloading libpcap source"):
                subprocess.run(['tar', '-xzf', '/tmp/libpcap.tar.gz', '-C', '/tmp/'], check=True)
                libpcap_dir = '/tmp/libpcap-1.10.4'
                if os.path.exists(libpcap_dir):
                    # Configure, compile and install
                    subprocess.run(['./configure', '--prefix=/usr/local'], cwd=libpcap_dir, check=True)
                    subprocess.run(['make'], cwd=libpcap_dir, check=True)
                    subprocess.run(['make', 'install'], cwd=libpcap_dir, check=True)
                    subprocess.run(['ldconfig'], check=True)  # Update library cache
                    print(f"{Colors.GREEN} libpcap built and installed from source{Colors.END}")
                    return True
        except Exception as e:
            print(f"{Colors.YELLOW} Source build failed: {e}{Colors.END}")
        
        return False
        
    except Exception as e:
        print(f"{Colors.RED} Alternative libpcap installation failed: {e}{Colors.END}")
        return False

def install_system_packages(distro_config: Dict) -> bool:
    """Install system packages based on distribution with anti-hang protection."""
    try:
        print(f"\n{Colors.BLUE} Phase 1: System Package Installation (Anti-Hang Protected){Colors.END}")

        # Phase 1a: Fix package locks (especially important for VMs)
        fix_package_locks()

        # Phase 1b: Repository update with timeout protection
        print(f"{Colors.WHITE}Updating package repository (timeout: 300s)...{Colors.END}")
        if not run_with_timeout(distro_config['update_cmd'], 300, "Repository update"):
            print(f"{Colors.YELLOW} Repository update failed, trying recovery...{Colors.END}")

            # Try Kali-specific repository fixes
            if 'kali' in str(distro_config.get('name', '')).lower():
                if fix_kali_repositories():
                    print(f"{Colors.GREEN} Kali repositories fixed{Colors.END}")
                else:
                    print(f"{Colors.YELLOW} Kali repository fix failed, continuing...{Colors.END}")
            
            # Try alternative update methods for Kali/Debian
            if not run_with_timeout(['apt', 'clean'], 60, "Cleaning apt cache"):
                print(f"{Colors.YELLOW}Cache cleaning failed, continuing anyway...{Colors.END}")
            else:
                if not run_with_timeout(['apt', 'update', '--allow-unauthenticated'], 180, "Alternative repository update"):
                    print(f"{Colors.YELLOW} Repository update issues detected, continuing with package installation...{Colors.END}")
        
        # Phase 1c: Check disk space before installation
        disk_usage = subprocess.run(['df', '/'], capture_output=True, text=True)
        if disk_usage.returncode == 0:
            lines = disk_usage.stdout.strip().split('\n')
            if len(lines) > 1:
                fields = lines[1].split()
                if len(fields) >= 4:
                    available_kb = int(fields[3])
                    available_gb = available_kb / (1024 * 1024)
                    print(f"{Colors.WHITE}Available disk space: {available_gb:.1f} GB{Colors.END}")
                    
                    if available_gb < 2.0:
                        print(f"{Colors.RED} CRITICAL: Less than 2GB disk space available! Installation may fail.{Colors.END}")
                        print(f"{Colors.YELLOW} Consider freeing up disk space before continuing.{Colors.END}")        # Phase 1c: Install only ESSENTIAL packages (minimal footprint to prevent disk space issues)
        print(f"{Colors.WHITE}Installing minimal essential packages (timeout per package: 180s)...{Colors.END}")
        
        # DRASTICALLY REDUCED package list to prevent disk space exhaustion
        # Added libpcap-dev to Stage 1 to prevent naabu compilation hanging issues
        essential_packages = ['curl', 'git', 'golang-go', 'libpcap-dev']  # Essential packages including libpcap for naabu
        development_packages = []  # Skip development packages for now
        final_packages = []  # Skip final packages for now

        # Initialize success counter
        success_count = 0
        total_packages = len(essential_packages)        # Install essential packages with non-interactive mode for safety
        for package in essential_packages:
            if package == 'libpcap-dev':
                # Special handling for libpcap-dev
                if run_with_timeout(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt', 'install', package, '-y'], 180, f"Installing {package}"):
                    success_count += 1
                else:
                    print(f"{Colors.YELLOW} {package} standard installation failed, trying alternatives...{Colors.END}")
                    if install_libpcap_alternative():
                        success_count += 1
                        print(f"{Colors.GREEN} {package} installed via alternative method{Colors.END}")
                    else:
                        print(f"{Colors.RED} {package} installation failed completely{Colors.END}")
            else:
                if run_with_timeout(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt', 'install', package, '-y'], 180, f"Installing {package}"):
                    success_count += 1
                else:
                    print(f"{Colors.YELLOW} {package} failed, but continuing...{Colors.END}")

        # Skip development and final packages to save disk space
        print(f"{Colors.WHITE}Skipping development and final packages to conserve disk space...{Colors.END}")        # Evaluate success
        success_rate = (success_count / total_packages) * 100 if total_packages > 0 else 0
        print(f"{Colors.GREEN} Minimal package installation completed: {success_count}/{total_packages} packages ({success_rate:.1f}%){Colors.END}")

        if success_count >= 3:  # At least curl, golang-go, and libpcap-dev must be installed
            return True
        else:
            print(f"{Colors.RED} Critical packages missing. Need at least curl, golang-go, and libpcap-dev.{Colors.END}")
            return False

    except Exception as e:
        print(f"{Colors.RED} Package installation failed: {e}{Colors.END}")
        return False

def setup_go_environment_complete() -> bool:
    """Complete Go environment setup with proper directory creation and validation."""
    try:
        print(f"\n{Colors.BLUE} Phase 2: Go Environment Setup{Colors.END}")
        
        # Check if Go is already properly installed
        go_installed = False
        try:
            result = subprocess.run(['go', 'version'], 
                                  capture_output=True, text=True, check=True)
            version = result.stdout.strip()
            print(f"{Colors.GREEN} Go already installed: {version}{Colors.END}")
            go_installed = True
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.YELLOW}  Go not found or improperly configured{Colors.END}")
        
        # Install/configure Go manually if needed
        if not go_installed:
            print(f"{Colors.WHITE}Installing Go manually...{Colors.END}")
            go_version = "1.21.5"
            go_archive = f"go{go_version}.linux-amd64.tar.gz"
            
            try:
                # Download Go
                subprocess.run([
                    'wget', '-q', 
                    f'https://golang.org/dl/{go_archive}',
                    '-O', f'/tmp/{go_archive}'
                ], check=True)
                
                # Extract Go
                subprocess.run(['sudo', 'tar', '-C', '/usr/local', '-xzf', f'/tmp/{go_archive}'], check=True)
                
                # Set up Go binary path
                go_bin = '/usr/local/go/bin'
                current_path = os.environ.get('PATH', '')
                if go_bin not in current_path:
                    os.environ['PATH'] = f"{go_bin}:{current_path}"
                    print(f"{Colors.GREEN} Added {go_bin} to PATH{Colors.END}")
                
                # Verify Go installation worked
                result = subprocess.run(['go', 'version'], 
                                      capture_output=True, text=True, check=True)
                version = result.stdout.strip()
                print(f"{Colors.GREEN} Go installed successfully: {version}{Colors.END}")
                
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED} Failed to install Go: {e}{Colors.END}")
                return False
        
        # Now set up GOPATH and GOBIN properly
        try:
            # Get GOPATH from Go environment
            gopath_result = subprocess.run(['go', 'env', 'GOPATH'], 
                                         capture_output=True, text=True, check=True)
            gopath = gopath_result.stdout.strip()
            
            if not gopath:
                # Set default GOPATH if not set
                gopath = os.path.expanduser('~/go')
                print(f"{Colors.WHITE}Setting GOPATH to default: {gopath}{Colors.END}")
            
            print(f"{Colors.WHITE}GOPATH: {gopath}{Colors.END}")
            
            # Ensure GOPATH directory exists
            if not os.path.exists(gopath):
                os.makedirs(gopath, exist_ok=True)
                print(f"{Colors.GREEN} Created GOPATH directory: {gopath}{Colors.END}")
            
            # Ensure GOPATH/bin directory exists (CRITICAL FIX)
            gobin = os.path.join(gopath, 'bin')
            if not os.path.exists(gobin):
                os.makedirs(gobin, exist_ok=True)
                print(f"{Colors.GREEN} Created GOBIN directory: {gobin}{Colors.END}")
            else:
                print(f"{Colors.GREEN} GOBIN directory exists: {gobin}{Colors.END}")
            
            # Ensure GOPATH/src directory exists (for older Go versions)
            gosrc = os.path.join(gopath, 'src')
            if not os.path.exists(gosrc):
                os.makedirs(gosrc, exist_ok=True)
                print(f"{Colors.GREEN} Created GOSRC directory: {gosrc}{Colors.END}")
            
            # Set proper permissions on Go directories
            import stat
            for go_dir in [gopath, gobin, gosrc]:
                if os.path.exists(go_dir):
                    os.chmod(go_dir, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            
            # Ensure GOBIN is in PATH for current session (CRITICAL FIX)
            current_path = os.environ.get('PATH', '')
            if gobin not in current_path:
                os.environ['PATH'] = f"{gobin}:{current_path}"
                print(f"{Colors.GREEN} Added {gobin} to current session PATH{Colors.END}")
            else:
                print(f"{Colors.GREEN} {gobin} already in PATH{Colors.END}")
            
            # Set Go environment variables for current session
            os.environ['GOPATH'] = gopath
            os.environ['GOBIN'] = gobin
            
            # Add to shell profiles for future sessions
            profile_lines = [
                'export PATH=$PATH:/usr/local/go/bin',
                f'export GOPATH={gopath}',
                f'export GOBIN={gobin}',
                'export PATH=$PATH:$GOBIN'
            ]
            
            for profile in ['.bashrc', '.zshrc']:
                profile_path = os.path.expanduser(f'~/{profile}')
                if os.path.exists(profile_path):
                    # Check if Go environment is already configured
                    with open(profile_path, 'r') as f:
                        content = f.read()
                    
                    if '# Go environment' not in content:
                        with open(profile_path, 'a') as f:
                            f.write('\n# Go environment\n')
                            for line in profile_lines:
                                f.write(f'{line}\n')
                        print(f"{Colors.GREEN} Added Go environment to {profile}{Colors.END}")
            
            # Final validation
            print(f"{Colors.WHITE}Validating Go environment...{Colors.END}")
            
            # Test Go command
            subprocess.run(['go', 'version'], check=True, capture_output=True)
            print(f"{Colors.GREEN}   Go command working{Colors.END}")
            
            # Test GOPATH
            if os.path.exists(gopath) and os.path.isdir(gopath):
                print(f"{Colors.GREEN}   GOPATH directory accessible{Colors.END}")
            else:
                print(f"{Colors.RED}   GOPATH directory issue{Colors.END}")
                return False
            
            # Test GOBIN
            if os.path.exists(gobin) and os.path.isdir(gobin):
                print(f"{Colors.GREEN}   GOBIN directory accessible{Colors.END}")
            else:
                print(f"{Colors.RED}   GOBIN directory issue{Colors.END}")
                return False
            
            # Test write permissions
            test_file = os.path.join(gobin, '.test_write')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                print(f"{Colors.GREEN}   GOBIN directory writable{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}   GOBIN directory not writable: {e}{Colors.END}")
                return False
            
            print(f"{Colors.GREEN} Go environment configured and validated successfully{Colors.END}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED} Go environment configuration failed: {e}{Colors.END}")
            return False
        
    except Exception as e:
        print(f"{Colors.RED} Go environment setup failed: {e}{Colors.END}")
        return False

def check_system_dependencies(distro: str) -> bool:
    """Check and install required system dependencies before Go tools installation."""
    try:
        print(f"\n{Colors.BLUE} Pre-installation: Dependency Verification{Colors.END}")
        
        if distro not in SUPPORTED_DISTROS:
            print(f"{Colors.RED} Unsupported distribution for dependency checking{Colors.END}")
            return False
            
        distro_config = SUPPORTED_DISTROS[distro]
        missing_deps = []
          # Define dependencies required for Go tools (libpcap-dev now handled in Stage 1)
        dependency_map = {
            'ubuntu': ['pkg-config', 'gcc'],
            'debian': ['pkg-config', 'gcc'],
            'kali': ['pkg-config', 'gcc'],
            'arch': ['pkgconfig', 'gcc']
        }
        
        required_deps = dependency_map.get(distro, [])
        
        print(f"{Colors.WHITE}Checking dependencies for {distro_config['name']}...{Colors.END}")
        
        # Check each dependency
        for dep in required_deps:
            if distro == 'arch':
                # Use pacman for Arch Linux
                try:
                    result = subprocess.run(['pacman', '-Q', dep], 
                                          capture_output=True, check=True)
                    print(f"{Colors.GREEN}   {dep} is installed{Colors.END}")
                except subprocess.CalledProcessError:
                    print(f"{Colors.RED}   {dep} is missing{Colors.END}")
                    missing_deps.append(dep)
            else:
                # Use dpkg for Debian-based systems
                try:
                    result = subprocess.run(['dpkg', '-l', dep], 
                                          capture_output=True, check=True)
                    if result.returncode == 0:
                        print(f"{Colors.GREEN}   {dep} is installed{Colors.END}")
                    else:
                        print(f"{Colors.RED}   {dep} is missing{Colors.END}")
                        missing_deps.append(dep)
                except subprocess.CalledProcessError:
                    print(f"{Colors.RED}   {dep} is missing{Colors.END}")
                    missing_deps.append(dep)
        
        # Install missing dependencies automatically
        if missing_deps:
            print(f"\n{Colors.YELLOW}Installing missing dependencies: {', '.join(missing_deps)}{Colors.END}")
            
            try:
                if distro == 'arch':
                    cmd = ['pacman', '-S', '--noconfirm'] + missing_deps
                else:
                    # Use non-interactive environment to prevent hanging
                    cmd = ['env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=a'] + distro_config['install_cmd'] + missing_deps
                
                subprocess.run(cmd, check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                
                for dep in missing_deps:
                    print(f"{Colors.GREEN}   {dep} installed successfully{Colors.END}")
                    
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED} Failed to install dependencies: {e}{Colors.END}")
                print(f"{Colors.YELLOW}Please install manually: {' '.join(missing_deps)}{Colors.END}")
                return False
        
        # Check for broken packages
        run_with_timeout(['apt', '--fix-broken', 'install', '-y'], 180, "Fixing broken packages")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED} Dependency verification failed: {e}{Colors.END}")
        return False

def verify_go_tools_prerequisites() -> bool:
    """Verify prerequisites for Go tools compilation."""
    try:
        print(f"{Colors.WHITE}Verifying Go tools prerequisites...{Colors.END}")
        
        # Enhanced pcap.h header search with more locations
        pcap_headers = [
            '/usr/include/pcap.h',
            '/usr/local/include/pcap.h',
            '/usr/include/pcap/pcap.h',
            '/usr/include/x86_64-linux-gnu/pcap.h',
            '/usr/include/*/pcap.h'
        ]
        
        pcap_found = False
        for header in pcap_headers:
            if '*' in header:
                # Use glob for wildcard patterns
                import glob
                matches = glob.glob(header)
                if matches:
                    print(f"{Colors.GREEN}   pcap.h found at {matches[0]}{Colors.END}")
                    pcap_found = True
                    break
            elif os.path.exists(header):
                print(f"{Colors.GREEN}   pcap.h found at {header}{Colors.END}")
                pcap_found = True
                break
        
        if not pcap_found:
            print(f"{Colors.YELLOW}   pcap.h header not found in standard locations{Colors.END}")
            
            # Try to install missing libpcap packages
            print(f"{Colors.WHITE}  Attempting to install missing libpcap packages...{Colors.END}")
            
            # Try different package names
            libpcap_variants = [
                'libpcap-dev',
                'libpcap0.8-dev',
                'libpcap-devel',
                'pcap-devel'
            ]
            
            for variant in libpcap_variants:
                if run_with_timeout(['apt', 'install', variant, '-y'], 120, f"Installing {variant}"):
                    # Check again after installation
                    for header in pcap_headers:
                        if '*' in header:
                            import glob
                            matches = glob.glob(header)
                            if matches:
                                print(f"{Colors.GREEN}   pcap.h now found at {matches[0]}{Colors.END}")
                                pcap_found = True
                                break
                        elif os.path.exists(header):
                            print(f"{Colors.GREEN}   pcap.h now found at {header}{Colors.END}")
                            pcap_found = True
                            break
                    if pcap_found:
                        break
            
            if not pcap_found:
                print(f"{Colors.RED}   Could not install or locate pcap.h{Colors.END}")
                print(f"{Colors.YELLOW}   naabu compilation may fail without pcap headers{Colors.END}")
                # Don't fail completely - let Go tools try anyway
                return True  # Changed from False to True to allow continuation
        
        # Check pkg-config for libpcap
        try:
            result = subprocess.run(['pkg-config', '--exists', 'libpcap'], 
                                  check=True, capture_output=True)
            print(f"{Colors.GREEN}   libpcap pkg-config found{Colors.END}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.YELLOW}   libpcap pkg-config not found, but continuing{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.YELLOW} Prerequisites verification failed: {e}{Colors.END}")
        return True  # Allow continuation even if verification fails

def attempt_dependency_recovery(distro: str) -> bool:
    """Attempt to recover from dependency installation failures."""
    try:
        print(f"\n{Colors.YELLOW} Attempting dependency recovery...{Colors.END}")
        
        distro_config = SUPPORTED_DISTROS[distro]
        
        # Clean package cache and update
        if distro == 'arch':
            print(f"{Colors.WHITE}Cleaning pacman cache...{Colors.END}")
            subprocess.run(['pacman', '-Scc', '--noconfirm'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['pacman', '-Sy'], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            print(f"{Colors.WHITE}Cleaning apt cache and updating...{Colors.END}")
            subprocess.run(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'clean'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'update'], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Try to fix broken packages
        if distro != 'arch':
            print(f"{Colors.WHITE}Fixing broken packages...{Colors.END}")
            subprocess.run(['env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=a', 'apt-get', 'install', '-f', '-y'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Retry dependency installation
        print(f"{Colors.WHITE}Retrying dependency installation...{Colors.END}")
        return check_system_dependencies(distro)
        
    except Exception as e:
        print(f"{Colors.RED} Recovery attempt failed: {e}{Colors.END}")
        return False

def clean_go_mod_cache(env_override: Optional[Dict[str, str]] = None):
    """Clean Go module cache to resolve download issues."""
    print(f"{Colors.YELLOW}Cleaning Go module cache...{Colors.END}")
    if run_with_timeout(['go', 'clean', '-modcache'], 120, "Cleaning Go module cache", allow_warnings=False, env_override=env_override):
        print(f"{Colors.GREEN}   Go module cache cleaned{Colors.END}")
    else:
        print(f"{Colors.YELLOW}   Could not clean Go module cache within timeout; continuing retry{Colors.END}")

def prepare_go_build_env(extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Prepare Go build environment using disk-backed temp/cache directories."""
    env = os.environ.copy()
    try:
        gopath = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    except Exception:
        gopath = os.path.expanduser("~/go")

    go_build_root = os.path.join(gopath, "mtscan-build")
    tmp_dir = os.path.join(go_build_root, "tmp")
    cache_dir = os.path.join(go_build_root, "cache")
    mod_cache_dir = os.path.join(go_build_root, "pkg", "mod")

    for directory in (tmp_dir, cache_dir, mod_cache_dir):
        os.makedirs(directory, exist_ok=True)

    env.update({
        "TMPDIR": tmp_dir,
        "GOTMPDIR": tmp_dir,
        "GOCACHE": cache_dir,
        "GOMODCACHE": mod_cache_dir,
        "CGO_ENABLED": "1",
        "GO111MODULE": "on",
        "GOPROXY": "https://proxy.golang.org,direct",
    })
    if extra_env:
        env.update(extra_env)

    print(f"{Colors.WHITE}  Go build temp/cache: {go_build_root}{Colors.END}")
    return env

def install_nuclei_with_retries(repo, max_retries=3):
    """Try to install nuclei with retries, cleaning cache and switching proxy if needed."""
    print(f"{Colors.WHITE}Installing/updating nuclei from {repo}...{Colors.END}")
    
    for attempt in range(1, max_retries+1):
        print(f"{Colors.WHITE}Installing nuclei (attempt {attempt}/{max_retries})...{Colors.END}")
        env = prepare_go_build_env()
        
        # On 2nd+ attempt, switch to direct proxy
        if attempt >= 2:
            env['GOPROXY'] = 'direct'
            print(f"{Colors.YELLOW}  Using GOPROXY=direct for retry{Colors.END}")
        else:
            env['GOPROXY'] = 'https://proxy.golang.org,direct'
        # On 2nd+ attempt, clean cache
        if attempt >= 2:
            clean_go_mod_cache(env)
        timeout_seconds = 600  # 10 min
        
        # Use -trimpath to remove local paths from binary
        returncode, stdout, stderr, timed_out = run_timed_command(
            ['go', 'install', '-v', '-trimpath', repo],
            timeout_seconds,
            env=env,
            capture_stdout=True,
        )
        
        if timed_out:
            print(f"{Colors.RED}   nuclei install timed out after {timeout_seconds}s; process tree was stopped{Colors.END}")
        elif returncode == 0:
            print(f"{Colors.GREEN}   nuclei installed/updated successfully{Colors.END}")
            try:
                gopath = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
                nuclei_path = os.path.join(gopath, 'bin', 'nuclei')
                if os.path.exists(nuclei_path):
                    expose_tool_to_path('nuclei', nuclei_path)
            except Exception:
                pass
            return True
        else:
            print(f"{Colors.RED}   nuclei install failed (exit {returncode}){Colors.END}")

        print(f"{Colors.YELLOW}  --- go install output ---{Colors.END}")
        print(stdout[-1000:])
        print(stderr[-1000:])
        if attempt == max_retries:
            print(f"{Colors.RED}   nuclei installation failed after {max_retries} attempts{Colors.END}")
            return False
        print(f"{Colors.YELLOW}  Retrying nuclei installation...{Colors.END}")
    return False

def install_security_tools_complete(distro: str) -> bool:
    """Install all security tools with enhanced dependency checking and error handling."""
    try:
        print(f"\n{Colors.BLUE} Phase 3: Security Tools Installation{Colors.END}")

        # Pre-installation dependency check with recovery
        if not check_system_dependencies(distro):
            print(f"{Colors.YELLOW}  Initial dependency check failed, attempting recovery...{Colors.END}")
            if not attempt_dependency_recovery(distro):
                print(f"{Colors.RED} System dependencies check failed after recovery attempt{Colors.END}")
                print(f"{Colors.WHITE}Manual intervention may be required{Colors.END}")
                return False
        
        # Verify Go tools prerequisites (libpcap-dev now guaranteed from Stage 1)
        if not verify_go_tools_prerequisites():
            print(f"{Colors.RED} Go tools prerequisites not met{Colors.END}")
            return False
        
        tools = {
            'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
            'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
        }
        
        success_count = 0
        
        for tool, repo in tools.items():
            if tool == 'nuclei':
                if install_nuclei_with_retries(repo, max_retries=3):
                    success_count += 1
                else:
                    print(f"{Colors.RED}   nuclei installation failed after multiple attempts{Colors.END}")
                    continue
            else:
                try:
                    print(f"{Colors.WHITE}Installing/updating {tool}...{Colors.END}")
                    existing_tool = find_scanner_binary(tool)
                    if existing_tool:
                        print(f"{Colors.YELLOW}   Existing {tool} found at {existing_tool}; updating to latest{Colors.END}")
                        if existing_tool.startswith("/root/go/bin/"):
                            expose_tool_to_path(tool, existing_tool)
                    env = prepare_go_build_env()
                    timeout_seconds = 600 if tool == 'naabu' else 450
                    if run_with_timeout(['go', 'install', '-v', '-trimpath', repo], timeout_seconds, f"Installing/updating {tool} (timeout: {timeout_seconds//60}min)", allow_warnings=False, env_override=env):
                        gopath = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
                        gobin = os.path.join(gopath, 'bin')
                        tool_path = os.path.join(gobin, tool)
                        print(f"{Colors.WHITE}  Verifying {tool} installation at {tool_path}...{Colors.END}")
                        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                            print(f"{Colors.GREEN}   {tool} installed and verified at {tool_path}{Colors.END}")
                            expose_tool_to_path(tool, tool_path)
                            success_count += 1
                        else:
                            print(f"{Colors.RED}   {tool} installation reported success but binary not found at {tool_path}{Colors.END}")
                    else:
                        print(f"{Colors.RED}   {tool} installation failed via go install{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}   Failed to install {tool}: {e}{Colors.END}")
          # Update nuclei templates if nuclei was installed (with optimization)
        nuclei_binary = find_scanner_binary('nuclei')
        if nuclei_binary:
            print(f"{Colors.WHITE}Updating nuclei templates (optimized)...{Colors.END}")
            try:
                # Use non-interactive mode and extended timeout for template updates
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                env['NUCLEI_DISABLE_COLORS'] = 'true'  # Prevent color codes from hanging terminal
                
                # Run with extended timeout and silent mode for faster processing
                result = subprocess.run([nuclei_binary, '-update-templates', '-silent'], 
                                      check=True, 
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.PIPE,
                                      timeout=300,  # Extended to 5 minutes
                                      env=env)
                print(f"{Colors.GREEN} Nuclei templates updated successfully{Colors.END}")
            except subprocess.TimeoutExpired:
                print(f"{Colors.YELLOW}  Template update timed out (5min) - continuing anyway{Colors.END}")
                print(f"{Colors.YELLOW}   Templates can be updated later: nuclei -update-templates{Colors.END}")
            except subprocess.CalledProcessError as e:
                print(f"{Colors.YELLOW}  Template update failed - continuing anyway{Colors.END}")
                if e.stderr:
                    error_msg = e.stderr.decode().strip()
                    if error_msg:
                        print(f"{Colors.YELLOW}  Error: {error_msg}{Colors.END}")
                print(f"{Colors.YELLOW}   Templates can be updated later: nuclei -update-templates{Colors.END}")
          # Evaluate installation success - nuclei is critical for vulnerability analysis
        if success_count >= 2:  # At least 2 out of 3 tools must be installed
            # Check if nuclei specifically was installed (critical for vulnerability scanning)
            if find_scanner_binary('nuclei'):
                print(f"{Colors.GREEN} Security tools installation completed ({success_count}/3 tools) - nuclei available{Colors.END}")
                return True
            else:
                print(f"{Colors.YELLOW}  {success_count}/3 tools installed but nuclei is missing{Colors.END}")
                print(f"{Colors.RED} Nuclei is critical for vulnerability analysis - installation incomplete{Colors.END}")
                print(f"{Colors.WHITE}The setup requires nuclei to be installed via 'go install' for proper operation{Colors.END}")
                return False
        else:
            print(f"{Colors.RED} Insufficient tools installed ({success_count}/3){Colors.END}")
            print(f"{Colors.WHITE}Minimum 2 tools required for operation{Colors.END}")
            return False
        
    except Exception as e:
        print(f"{Colors.RED} Security tools installation failed: {e}{Colors.END}")
        return False

def install_python_dependencies() -> bool:
    """Install Python dependencies for enhanced functionality."""
    try:
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        requirements_file = os.path.join(script_dir, 'config', 'requirements.txt')
        
        if os.path.exists(requirements_file):
            print(f"{Colors.WHITE}Installing Python dependencies from requirements.txt...{Colors.END}")
            subprocess.run(['pip3', 'install', '-r', requirements_file], check=True, 
                          stdout=subprocess.DEVNULL)
            print(f"{Colors.GREEN} Python dependencies installed{Colors.END}")
        else:
            # Fallback essential packages
            print(f"{Colors.WHITE}Installing essential Python packages...{Colors.END}")
            essential_packages = [
                'cassandra-driver>=3.29,<4',
            ]
            
            for package in essential_packages:
                subprocess.run(['pip3', 'install', package], check=True, 
                              stdout=subprocess.DEVNULL)
                print(f"{Colors.GREEN}   {package}{Colors.END}")
            
        return True
    except Exception as e:
        print(f"{Colors.RED} Python dependencies installation failed: {e}{Colors.END}")
        return False

def setup_python_environment() -> bool:
    """Setup Python environment, handling externally-managed environments like Kali Linux."""
    try:
        print(f"\n{Colors.BLUE} Setting up Python environment{Colors.END}")
        
        # Check if we're in an externally-managed environment (Kali Linux)
        try:
            result = subprocess.run(['pip', '--version'], capture_output=True, text=True)
            if result.returncode != 0 or 'externally-managed' in result.stderr.lower():
                print(f"{Colors.YELLOW} Detected externally-managed Python environment (likely Kali Linux){Colors.END}")
                
                # Check if python3-venv is available
                venv_check = subprocess.run(['python3', '-m', 'venv', '--help'], capture_output=True, text=True)
                if venv_check.returncode != 0:
                    print(f"{Colors.WHITE}Installing python3-venv...{Colors.END}")
                    if not run_with_timeout(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt', 'install', 'python3-venv', '-y'], 180, "Installing python3-venv"):
                        print(f"{Colors.RED} Failed to install python3-venv{Colors.END}")
                        return False
                
                # Create virtual environment in user directory
                venv_path = os.path.expanduser("~/vulnerability_analysis_venv")
                if not os.path.exists(venv_path):
                    print(f"{Colors.WHITE}Creating virtual environment at {venv_path}...{Colors.END}")
                    if not run_with_timeout(['python3', '-m', 'venv', venv_path], 120, "Creating virtual environment"):
                        print(f"{Colors.RED} Failed to create virtual environment{Colors.END}")
                        return False
                
                # Activate virtual environment by setting environment variables
                venv_bin = os.path.join(venv_path, 'bin')
                os.environ['VIRTUAL_ENV'] = venv_path
                os.environ['PATH'] = f"{venv_bin}:{os.environ.get('PATH', '')}"
                
                print(f"{Colors.GREEN} Virtual environment created and activated{Colors.END}")
                print(f"{Colors.WHITE}Virtual environment path: {venv_path}{Colors.END}")
                
                # Add activation instructions to shell profiles
                activation_cmd = f"source {venv_path}/bin/activate"
                profile_comment = "# Vulnerability Analysis Virtual Environment"
                
                for profile in ['.bashrc', '.zshrc']:
                    profile_path = os.path.expanduser(f'~/{profile}')
                    if os.path.exists(profile_path):
                        with open(profile_path, 'r') as f:
                            content = f.read()
                        
                        if profile_comment not in content:
                            with open(profile_path, 'a') as f:
                                f.write(f'\n{profile_comment}\n')
                                f.write(f'# {activation_cmd}\n')
                
                return True
            else:
                print(f"{Colors.GREEN} Standard Python environment detected{Colors.END}")
                return True
                
        except Exception as e:
            print(f"{Colors.YELLOW} Python environment check failed: {e}{Colors.END}")
            return True  # Continue anyway
            
    except Exception as e:
        print(f"{Colors.RED} Python environment setup failed: {e}{Colors.END}")
        return False

def create_configuration_files() -> bool:
    """Create optimized configuration files."""
    try:
        print(f"\n{Colors.BLUE}  Phase 4: Configuration Optimization{Colors.END}")
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_dir = os.path.join(script_dir, 'config')
        
        # Create config directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        
        # Create optimized configuration
        config = {
            "general": {
                "max_threads": 50,
                "timeout": 3600,
                "optimize_for_linux": True,
                "platform": "linux",
                "installation_date": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "naabu": {
                "threads": 100,
                "rate": 1000,
                "timeout": 3,
                "top_ports": "1000",
                "exclude_ports": "443,80"
            },
            "httpx": {
                "threads": 100,
                "timeout": 5,
                "max_redirects": 3,
                "follow_redirects": True,
                "status_code": True
            },
            "nuclei": {
                "rate_limit": 200,
                "bulk_size": 50,
                "timeout": 5,
                "update_templates": True,
                "severity": ["critical", "high", "medium"]
            },
            "tools_paths": {
                "naabu": shutil.which('naabu') or 'naabu',
                "httpx": shutil.which('httpx') or 'httpx',
                "nuclei": shutil.which('nuclei') or 'nuclei'
            }
        }
        
        config_file = os.path.join(config_dir, 'optimized_config.json')
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"{Colors.GREEN} Configuration file created: {config_file}{Colors.END}")
        
        # Create bash aliases for easy access
        aliases_content = '''#!/bin/bash
# Vulnerability Analysis Toolkit Aliases
alias vat-scan="python3 $(find . -name 'workflow.py' 2>/dev/null | head -1)"
alias vat-naabu="naabu"
alias vat-httpx="httpx"
alias vat-nuclei="nuclei"
alias vat-update="nuclei -update-templates"
'''
        
        aliases_file = os.path.join(config_dir, 'vat_aliases.sh')
        with open(aliases_file, 'w') as f:
            f.write(aliases_content)
        os.chmod(aliases_file, 0o755)
        
        print(f"{Colors.GREEN} Aliases created: {aliases_file}{Colors.END}")
        print(f"{Colors.YELLOW} To use aliases: source {aliases_file}{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED} Configuration creation failed: {e}{Colors.END}")
        return False

def final_verification() -> bool:
    """Comprehensive final verification."""
    try:
        print(f"\n{Colors.BLUE} Phase 5: Final Verification{Colors.END}")
        
        tools_to_check = ['naabu', 'httpx', 'nuclei', 'go']
        all_good = True
        
        print(f"{Colors.WHITE}Checking tool availability...{Colors.END}")
        for tool in tools_to_check:
            tool_path = shutil.which(tool) if tool == "go" else find_scanner_binary(tool)
            tool_found = tool_path is not None
            
            if tool_found:
                print(f"{Colors.GREEN}   {tool}: Available at {tool_path}{Colors.END}")
            else:
                print(f"{Colors.RED}   {tool}: Not found{Colors.END}")
                all_good = False
          
        # Test basic functionality with enhanced path detection
        print(f"{Colors.WHITE}Testing tool functionality...{Colors.END}")
        
        # Test nuclei
        nuclei_path = find_scanner_binary('nuclei')
        if nuclei_path:
            try:
                result = subprocess.run([nuclei_path, '-version'], 
                                      capture_output=True, text=True, 
                                      timeout=10, check=True)
                print(f"{Colors.GREEN}   nuclei: {result.stdout.strip()}{Colors.END}")
            except:
                print(f"{Colors.YELLOW}    nuclei: Version check failed{Colors.END}")
        else:
            print(f"{Colors.YELLOW}    nuclei: Not found for testing{Colors.END}")
        
        # Test naabu
        naabu_path = find_scanner_binary('naabu')
        if naabu_path:
            try:
                result = subprocess.run([naabu_path, '-version'], 
                                      capture_output=True, text=True, 
                                      timeout=10, check=True)
                print(f"{Colors.GREEN}   naabu: Working{Colors.END}")
            except:
                print(f"{Colors.YELLOW}    naabu: Version check failed{Colors.END}")
        else:
            print(f"{Colors.YELLOW}    naabu: Not found for testing{Colors.END}")
        
        # Test httpx
        httpx_path = find_scanner_binary('httpx')
        if httpx_path:
            try:
                result = subprocess.run(
                    [httpx_path, '-version'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        [httpx_path, '-h'],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=True,
                    )
                print(f"{Colors.GREEN}   httpx: Working{Colors.END}")
            except:
                print(f"{Colors.YELLOW}    httpx: Version check failed{Colors.END}")
        else:
            print(f"{Colors.YELLOW}    httpx: Not found for testing{Colors.END}")
        
        # Enhanced success criteria - if tools are found even if not in PATH, consider it success
        tools_found = 0
        for tool in ['naabu', 'httpx', 'nuclei']:
            if find_scanner_binary(tool):
                tools_found += 1
        
        if tools_found >= 2:  # At least 2 out of 3 tools found
            print(f"{Colors.GREEN} Verification passed: {tools_found}/3 tools found{Colors.END}")
            if tools_found < 3:
                print(f"{Colors.YELLOW} Re-run setup or check /usr/local/bin permissions.{Colors.END}")
            return True
        else:
            print(f"{Colors.RED} Insufficient tools found: {tools_found}/3{Colors.END}")
            return False
        
    except Exception as e:
        print(f"{Colors.RED} Verification failed: {e}{Colors.END}")
        return False

def print_success_message():
    """Print successful installation message."""
    print(f"\n{Colors.GREEN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}INSTALLATION COMPLETED SUCCESSFULLY!{Colors.END}")
    print(f"{Colors.GREEN}{'='*80}{Colors.END}")
    print(f"{Colors.WHITE} Your Linux Vulnerability Analysis Toolkit is ready!{Colors.END}")
    print(f"\n{Colors.CYAN}Tool PATH:{Colors.END}")
    print(f"{Colors.WHITE}  Scanner binaries are exposed through /usr/local/bin when setup runs with sudo.{Colors.END}")
    print(f"{Colors.WHITE}  If your shell cannot find them, run: export PATH=$PATH:/usr/local/bin{Colors.END}")
    print(f"\n{Colors.CYAN}Next Steps:{Colors.END}")
    print(f"{Colors.WHITE}1. Navigate to the project directory{Colors.END}")
    print(f"{Colors.WHITE}2. Test: python3 src/workflow.py --check-tools{Colors.END}")
    print(f"{Colors.WHITE}3. Open the menu: python3 mtscan.py{Colors.END}")
    print(f"{Colors.WHITE}4. Run scans: python3 src/workflow.py --all -host <target>{Colors.END}")
    print(f"{Colors.WHITE}5. Check config/optimized_config.json for settings{Colors.END}")
    print(f"\n{Colors.CYAN}Example Usage:{Colors.END}")
    print(f"{Colors.WHITE}  python3 src/workflow.py --all -host example.com --top-ports 100 --save-output{Colors.END}")
    print(f"{Colors.WHITE}  python3 src/workflow.py -httpx -host example.com --title --status-code{Colors.END}")
    print(f"\n{Colors.GREEN}{'='*80}{Colors.END}")

def check_disk_space(min_gb: float = 2.0) -> bool:
    """Check available disk space and warn if insufficient."""
    try:
        disk_usage = subprocess.run(['df', '/'], capture_output=True, text=True)
        if disk_usage.returncode == 0:
            lines = disk_usage.stdout.strip().split('\n')
            if len(lines) > 1:
                fields = lines[1].split()
                if len(fields) >= 4:
                    available_kb = int(fields[3])
                    available_gb = available_kb / (1024 * 1024)
                    used_kb = int(fields[2])
                    used_gb = used_kb / (1024 * 1024)
                    total_kb = int(fields[1])
                    total_gb = total_kb / (1024 * 1024)
                    
                    print(f"{Colors.WHITE} Disk Space Status:{Colors.END}")
                    print(f"   Total: {total_gb:.1f} GB")
                    print(f"   Used: {used_gb:.1f} GB")
                    print(f"   Available: {available_gb:.1f} GB")
                    
                    if available_gb < min_gb:
                        print(f"{Colors.RED} CRITICAL: Less than {min_gb:.1f}GB disk space available!{Colors.END}")
                        print(f"{Colors.YELLOW} Installation may fail due to insufficient disk space.{Colors.END}")
                        print(f"{Colors.WHITE} Recommendations:{Colors.END}")
                        print(f"   - Free up disk space by removing unused files")
                        print(f"   - Use 'sudo apt clean' to clear package cache")
                        print(f"   - Use 'sudo apt autoremove' to remove unused packages")
                        return False
                    else:
                        print(f"{Colors.GREEN} Sufficient disk space available{Colors.END}")
                        return True
        return True  # If we can't check, assume it's okay
    except Exception as e:
        print(f"{Colors.YELLOW} Could not check disk space: {e}{Colors.END}")
        return True  # Continue anyway

def main():
    """Main installation orchestrator with complete multi-phase setup."""
    try:
        # Print header
        print_header()
          # Phase 0: System validation and environment checks
        print(f"{Colors.BLUE} Phase 0: System Validation & Environment Checks{Colors.END}")
        
        # Check root permissions first
        if not check_root_permissions():
            return False
        
        # Check disk space before starting installation
        if not check_disk_space(min_gb=2.0):
            response = input(f"{Colors.YELLOW}Continue anyway? (y/N): {Colors.END}")
            if response.lower() != 'y':
                print(f"{Colors.RED} Installation cancelled due to insufficient disk space{Colors.END}")
                return False
        
        # Validate system requirements
        valid, distro = validate_system_requirements()
        if not valid or not distro:
            return False
        
        distro_config = SUPPORTED_DISTROS[distro]
        print(f"{Colors.GREEN} System validation passed{Colors.END}")
        
        # Installation phases with optimized order
        phases = [
            ("Python Environment Setup", setup_python_environment),
            ("Minimal System Packages", lambda: install_system_packages(distro_config)),
            ("Go Environment", setup_go_environment_complete),
            ("Security Tools", lambda: install_security_tools_complete(distro)),
            ("Configuration", create_configuration_files),
            ("Final Verification", final_verification)
        ]
        
        for phase_name, phase_func in phases:
            if not phase_func():
                print(f"\n{Colors.RED} Installation failed at: {phase_name}{Colors.END}")
                print(f"{Colors.WHITE}Please check the error messages above and try again{Colors.END}")
                return False
        
        # Success!
        print_success_message()
        
        # Auto-launch MTScan menu
        try:
            response = input(" Launch MTScan interactive menu now? [Y/n]: ").strip().lower()
            if response in ['', 'y', 'yes']:
                print("\n Launching MTScan...")
                print("=" * 40)
                print(f"{Colors.YELLOW}Note: If tools show as 'Not installed', run: export PATH=$PATH:/usr/local/bin{Colors.END}")
                # Change to the parent directory and launch mtscan from root
                parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                mtscan_path = os.path.join(parent_dir, "mtscan.py")
                if os.path.exists(mtscan_path):
                    subprocess.run(["python", mtscan_path], cwd=parent_dir)
                else:
                    print(" Could not find mtscan.py. Please run it manually.")
            else:
                print("\n Setup complete! Run 'python3 mtscan.py' when ready.")
                print(f"{Colors.YELLOW}If needed: export PATH=$PATH:/usr/local/bin{Colors.END}")
        except KeyboardInterrupt:
            print("\n\n Setup complete! Run 'python3 mtscan.py' when ready.")
            print(f"{Colors.YELLOW}If needed: export PATH=$PATH:/usr/local/bin{Colors.END}")
        
        return True
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED} Installation cancelled by user{Colors.END}")
        return False
    except Exception as e:
        print(f"\n{Colors.RED} Unexpected error during installation: {e}{Colors.END}")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED} Installation cancelled by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED} Unexpected error: {e}{Colors.END}")
        sys.exit(1)
