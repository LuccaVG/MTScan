#!/usr/bin/env python3
"""
mtscan.py - Multi Tool Scan Interactive Menu
Main interface for the Linux Vulnerability Analysis Toolkit
"""

import os
import sys
import platform
import subprocess
import datetime
import shutil
import socket
import re
import ipaddress
import urllib.parse
import threading
import signal
import time
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import utils for tool detection
try:
    from src.utils import get_executable_path
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False
    def get_executable_path(cmd):
        """Fallback function if utils not available."""
        try:
            result = subprocess.run(['which', cmd], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        return None

try:
    from src.tool_runner import is_informational_finding_line, is_security_finding_line
except ImportError:
    def is_security_finding_line(line):
        return False

    def is_informational_finding_line(line):
        return False

# Ensure we're running on Linux
if platform.system().lower() != "linux":
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│                             ERROR                               │")
    print("│                                                                 │")
    print("│     This toolkit is designed EXCLUSIVELY for Linux systems      │")
    print("│                                                                 │")
    print("│          Supported: Debian, Kali, Ubuntu, Arch Linux            │")
    print("│              NOT Supported: Windows, macOS, WSL                 │")
    print("│                                                                 │")
    print("│        Please use a native Linux environment for optimal        │")
    print("│           security tool performance and compatibility.          │")
    print("└─────────────────────────────────────────────────────────────────┘")
    sys.exit(1)

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

def print_banner():
    """Print the MTScan banner."""
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                          ║")
    print("║          ███╗   ███╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗          ║")
    print("║          ████╗ ████║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║          ║")
    print("║          ██╔████╔██║   ██║   ███████╗██║     ███████║██╔██╗ ██║          ║")
    print("║          ██║╚██╔╝██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║          ║")
    print("║          ██║ ╚═╝ ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║          ║")
    print("║          ╚═╝     ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝          ║")
    print("║                                                                          ║")
    print("║                   Multi Tool Scan - Interactive Menu                     ║")
    print("║                  Linux Vulnerability Analysis Toolkit                    ║")
    print("║                                                                          ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print()

def find_tool_path(tool_name):
    """Find tool path using multiple methods to handle different installations."""
    # Common installation paths (order matters - prefer system packages first)
    search_paths = [
        f"/usr/bin/{tool_name}",           # System package (apt, yum, etc.)
        f"/usr/local/bin/{tool_name}",     # Manual system-wide installation
        f"/snap/bin/{tool_name}",          # Snap package
        f"{os.path.expanduser('~')}/go/bin/{tool_name}",  # User Go installation
        f"/root/go/bin/{tool_name}",       # Root Go installation
        f"{os.path.expanduser('~')}/.local/bin/{tool_name}",  # Local user installation
        f"/opt/{tool_name}/{tool_name}",   # Custom installation directory
    ]
    
    # Special case for Kali Linux httpx
    if tool_name == "httpx":
        search_paths.insert(1, "/usr/bin/httpx-toolkit")
    
    # First try using utils if available
    if UTILS_AVAILABLE:
        path_result = get_executable_path(tool_name)
        if path_result and verify_tool_works(path_result):
            return path_result
    
    # Fallback: try to find in PATH
    try:
        result = subprocess.run(['which', tool_name], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            tool_path = result.stdout.strip()
            if verify_tool_works(tool_path):
                return tool_path
    except:
        pass
    
    # Then check common paths
    for path in search_paths:
        expanded_path = os.path.expanduser(path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            if verify_tool_works(expanded_path):
                return expanded_path
    
    # Additional check for Go tools in current user's GOPATH
    try:
        gopath_result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True, timeout=5)
        if gopath_result.returncode == 0:
            gopath = gopath_result.stdout.strip()
            go_tool_path = os.path.join(gopath, 'bin', tool_name)
            if os.path.exists(go_tool_path) and verify_tool_works(go_tool_path):
                return go_tool_path
    except:
        pass
    
    return None

def verify_tool_works(tool_path):
    """Verify that a tool actually works by running a simple command."""
    try:
        # Try common version/help flags
        for flag in ["--version", "-version", "-v", "--help", "-h"]:
            try:
                result = subprocess.run([tool_path, flag], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True
            except:
                continue
        return False
    except:
        return False

def check_tools_status():
    """Check the status of required tools with flexible path detection."""
    tools = ['naabu', 'httpx', 'nuclei']
    status = {}
    
    for tool in tools:
        tool_path = find_tool_path(tool)
        status[tool] = {
            'installed': tool_path is not None,
            'path': tool_path
        }
    
    return status

def print_tools_status():
    """Print enhanced tool status with detailed information."""
    print("TOOL STATUS CHECK:")
    print("=" * 60)
    
    status = check_tools_status()
    
    all_tools_ready = True
    for tool, info in status.items():
        if info['installed']:
            print(f"  [OK]      {tool.upper():<8} Available at {info['path']}")
        else:
            print(f"  [MISSING] {tool.upper():<8} Not found in system PATH")
            all_tools_ready = False
    
    if all_tools_ready:
        print(f"\n[STATUS] All security tools are installed and ready")
        print(f"[READY]  System prepared for vulnerability scanning")
    else:
        missing_tools = [tool for tool, info in status.items() if not info['installed']]
        print(f"\n[WARNING] Missing tools: {', '.join(missing_tools)}")
        print(f"[ACTION]  Run option [8] to install or update tools")
        print(f"[PATH]    Ensure /usr/local/bin is in PATH: export PATH=$PATH:/usr/local/bin")
    
    print()

def print_main_menu():
    """Print enhanced main menu with better formatting."""
    print("SCAN OPERATIONS:")
    print("=" * 60)
    print("  [1] Port Discovery Scan      (naabu)")
    print("      Fast port enumeration and service detection")
    print()
    print("  [2] HTTP Service Analysis    (httpx)")
    print("      Web service discovery and technology detection")
    print()
    print("  [3] Vulnerability Assessment (nuclei)")
    print("      Security vulnerability scanning with 5000+ templates")
    print()
    print("  [4] Complete Scan Chain       (naabu -> httpx -> nuclei)")
    print("      Run port discovery, service analysis, and vulnerability checks")
    print()
    print("MANAGEMENT OPERATIONS:")
    print("=" * 60)
    print("  [5] View Previous Results")
    print("      Browse and analyze past scan results")
    print()
    print("  [6] Update Nuclei Templates")
    print("      Download latest vulnerability templates")
    print()
    print("  [7] Tool Configuration")
    print("      Configure scanning parameters and settings")
    print()
    print("  [8] Install/Update Tools")
    print("      Install or update security scanning tools")
    print()
    print("  [9] Help & Documentation")
    print("      View usage guides and tool documentation")
    print()
    print("  [0] Exit Program")
    print("=" * 60)
    print()

def get_target_input():
    """Get target input from user with comprehensive validation and help."""
    while True:
        print("\nTARGET SPECIFICATION:")
        print("Enter your scan target. Examples:")
        print("  - IP Address: 192.168.1.100")
        print("  - Domain: example.com")
        print("  - URL: https://example.com (domain will be extracted)")
        print("  - Localhost: 127.0.0.1 or localhost")
        print()
        print("TIP: Use 'help' for target format examples")
        
        target = input("Enter target: ").strip()
        
        if target.lower() == 'help':
            print("\n" + "="*50)
            print("TARGET FORMAT EXAMPLES:")
            print("="*50)
            print("VALID formats:")
            print("  192.168.1.1        - IPv4 address")
            print("  10.0.0.1           - Private IP")
            print("  example.com        - Domain name")
            print("  test.example.com   - Subdomain")
            print("  localhost          - Local system")
            print("  127.0.0.1          - Loopback IP")
            print()
            print("INVALID formats:")
            print("  999.999.999.999    - Invalid IP octets")
            print("  just-text          - Not a valid domain")
            print("  http://example     - Incomplete URL")
            print("  192.168.1          - Incomplete IP")
            print("="*50)
            continue
        
        if not target:
            print("ERROR: Target cannot be empty. Please enter a valid IP or domain.")
            continue
        
        # Validate the target
        is_valid, result = validate_target_input(target)
        
        if is_valid:
            validated_target = result
            print(f"VALID target: {validated_target}")
            
            # Show scan confirmation with legal notice
            if get_safe_scan_confirmation(validated_target, "security scan"):
                return validated_target
            else:
                continue  # User declined, ask for target again
        else:
            print(f"ERROR: {result}")
            print("Please try again or type 'help' for examples.")
            continue

def get_ports_input():
    """Get ports input for naabu scan."""
    print("\nPort Selection:")
    print("  [1] Top 100 ports")
    print("  [2] Top 1000 ports (default)")
    print("  [3] All ports (1-65535)")
    print("  [4] Number of ports to scan")
    
    while True:
        choice = input("\nSelect option [1-4]: ")

        if choice == "1":
            return "top-100"
        elif choice == "2" or choice == "":
            return "top-1000"
        elif choice == "3":
            return "1-65535"
        elif choice == "4":
            while True:
                try:
                    num_ports = input("Enter number of ports to scan (e.g., 30000): ").strip()
                    port_count = int(num_ports)
                    if port_count > 0 and port_count <= 65535:
                        return f"top-{port_count}"
                    else:
                        print("Please enter a number between 1 and 65535.")
                except ValueError:
                    print("Please enter a valid number.")
        else:
            print("Invalid option. Please select 1-4.")


def get_yes_no(prompt, default=False):
    """Prompt for a yes/no answer."""
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{prompt} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def get_complete_chain_flags():
    """Choose preset or custom settings for the full naabu -> httpx -> nuclei chain."""
    print("\n" + "="*60)
    print("COMPLETE SCAN CHAIN CONFIGURATION")
    print("="*60)
    print("Choose how the chain should run:")
    print("  [1] Default chain")
    print("      naabu top 1000 ports, httpx web fingerprinting, nuclei defaults")
    print("  [2] Fast chain")
    print("      top 100 ports, lower noise, critical/high nuclei checks")
    print("  [3] Stealth chain")
    print("      lower rate, connect scan, no Interactsh callbacks")
    print("  [4] Deep chain")
    print("      all ports, richer httpx details, critical/high/medium/low nuclei")
    print("  [5] Custom per-tool configuration")
    print("      choose naabu, httpx, and nuclei flags separately")

    while True:
        choice = input("\nSelect chain mode [1-5]: ").strip() or "1"

        if choice == "1":
            return {}
        if choice == "2":
            return {
                "ports": "top-100",
                "scan_type": "connect",
                "title": True,
                "status_code": True,
                "tech_detect": True,
                "web_server": True,
                "severity": "critical,high",
            }
        if choice == "3":
            return {
                "stealth": True,
                "ports": "top-1000",
                "scan_type": "connect",
                "rate": 10,
                "threads": 25,
                "nuclei_rate_limit": 5,
                "concurrency": 5,
                "parallel_processing": 5,
                "no_interactsh": True,
            }
        if choice == "4":
            return {
                "ports": "1-65535",
                "scan_type": "connect",
                "title": True,
                "status_code": True,
                "tech_detect": True,
                "web_server": True,
                "content_length": True,
                "response_time": True,
                "severity": "critical,high,medium,low",
            }
        if choice == "5":
            selected_flags = {}
            if get_yes_no("Configure naabu port discovery?", True):
                show_scan_type_help("naabu")
                selected_flags.update(get_naabu_flags())
            if get_yes_no("Configure httpx service analysis?", True):
                show_scan_type_help("httpx")
                selected_flags.update(get_httpx_flags())
            if get_yes_no("Configure nuclei vulnerability checks?", True):
                show_scan_type_help("nuclei")
                selected_flags.update(get_nuclei_flags())
            return selected_flags

        print("Invalid option. Please select 1-5.")



def run_scan(scan_type, target, **kwargs):
    """Run a scan with enhanced real-time output and comprehensive flag support."""
      # Get flags for the selected scan type
    if scan_type == "naabu":
        print(f"\nConfiguring NAABU port scanner for target: {target}")
        show_scan_type_help("naabu")
        flags = get_naabu_flags()
    elif scan_type == "httpx":
        print(f"\nConfiguring HTTPX HTTP service detection for target: {target}")
        show_scan_type_help("httpx")
        flags = get_httpx_flags()
    elif scan_type == "nuclei":
        print(f"\nConfiguring NUCLEI vulnerability scanner for target: {target}")
        show_scan_type_help("nuclei")
        flags = get_nuclei_flags()
    elif scan_type == "all":
        print(f"\nConfiguring COMPLETE scan chain for target: {target}")
        print("This will run naabu, then pass discovered services to httpx, then pass HTTP targets to nuclei.")
        flags = get_complete_chain_flags()
    else:
        print(f"ERROR: Unknown scan type: {scan_type}")
        return False
      # Set defaults - outputs always enabled by default
    save_output = True  # Always save output
    json_output = False  # Default to text format
    stealth_mode = False  # Not used anymore, but needed for compatibility
    tool_silent = False  # Not used anymore, but needed for compatibility
      # Enhanced configuration summary
    print(f"\n{'=' * 60}")
    print("SCAN CONFIGURATION SUMMARY")
    print("=" * 60)
    print(f"[TOOL]           {scan_type.upper()}")
    print(f"[TARGET]         {target}")
    print(f"[SAVE OUTPUT]    ENABLED (always)")
    print(f"[OUTPUT FORMAT]  TEXT (default)")
    print(f"[REAL-TIME]      ENABLED")
    print(f"[FLAGS COUNT]    {len(flags)}")
    
    if flags:
        print(f"\n[ACTIVE FLAGS]")
        for flag, value in flags.items():
            if isinstance(value, bool) and value:
                print(f"  + {flag}")
            elif not isinstance(value, bool):
                display_value = str(value)
                if len(display_value) > 50:
                    display_value = display_value[:47] + "..."
                print(f"  + {flag}: {display_value}")
    else:
        print(f"\n[FLAGS] Using default configuration")
    
    print("=" * 60)
    
    # Final confirmation with enhanced display
    print(f"\n[READY TO START] All parameters configured")
    proceed = input("[CONFIRM] Proceed with scan? [Y/n]: ").strip().lower()
    if proceed in ['n', 'no']:
        print("[CANCELLED] Scan cancelled by user.")
        return False
    
    # Build command
    cmd = [sys.executable, "src/workflow.py"]
    
    # Add tool-specific flag
    if scan_type == "naabu":
        cmd.append("-naabu")
    elif scan_type == "httpx":
        cmd.append("-httpx")
    elif scan_type == "nuclei":
        cmd.append("-nuclei")
    elif scan_type == "all":
        cmd.append("--all")
    
    # Add target
    cmd.extend(["-host", target])
    
    # Add basic options
    if stealth_mode:
        cmd.append("-s")
    
    if tool_silent:
        cmd.append("--tool-silent")
    
    if save_output:
        cmd.append("--save-output")
    
    if json_output:
        cmd.append("--json-output")
      # Add all flag-specific arguments
    for flag, value in flags.items():
        if flag == 'stealth' and value:
            cmd.append("-s")
        elif flag == 'ports' and value:
            # Handle the top-N format correctly for naabu
            if str(value).startswith('top-'):
                try:
                    # Extract N from "top-N" format
                    num_ports = str(value).split("-")[1]
                    cmd.extend(["--top-ports", num_ports])
                except (IndexError, ValueError):
                    # Fallback to passing the value as is
                    cmd.extend(["-p", str(value)])
            else:
                # Handle regular port specifications
                cmd.extend(["-p", str(value)])
        elif flag == 'threads' and value:
            cmd.extend(["--threads", str(value)])
        elif flag == 'rate' and value:
            cmd.extend(["--rate", str(value)])
        elif flag == 'exclude_ports' and value:
            cmd.extend(["--exclude-ports", str(value)])
        elif flag == 'scan_type' and value:
            cmd.extend(["--scan-type", str(value)])
        elif flag == 'naabu_timeout' and value:
            cmd.extend(["--naabu-timeout", str(value)])
        elif flag == 'naabu_retries' and value:
            cmd.extend(["--naabu-retries", str(value)])
        elif flag == 'top_ports' and value:
            cmd.extend(["--top-ports", str(value)])
        elif flag == 'source_port' and value:
            cmd.extend(["--source-port", str(value)])
        elif flag == 'interface' and value:
            cmd.extend(["--interface", str(value)])
        elif flag == 'host_discovery' and value:
            cmd.append("--host-discovery")
        elif flag == 'ping' and value:
            cmd.append("--ping")
        elif flag == 'no_ping' and value:
            cmd.append("--no-ping")
        elif flag == 'naabu_debug' and value:
            cmd.append("--naabu-debug")
        elif flag == 'naabu_json' and value:
            cmd.append("--naabu-json")
        elif flag == 'naabu_csv' and value:
            cmd.append("--naabu-csv")
          # HTTPX flags
        elif flag == 'title' and value:
            cmd.append("--title")
        elif flag == 'status_code' and value:
            cmd.append("--status-code")
        elif flag == 'tech_detect' and value:
            cmd.append("--tech-detect")
        elif flag == 'web_server' and value:
            cmd.append("--web-server")
        elif flag == 'follow_redirects' and value:
            cmd.append("--follow-redirects")
        elif flag == 'rate_limit' and value:
            cmd.extend(["--rate-limit", str(value)])
        elif flag == 'content_length' and value:
            cmd.append("--content-length")
        elif flag == 'response_time' and value:
            cmd.append("--response-time")
        elif flag == 'httpx_timeout' and value:
            cmd.extend(["--httpx-timeout", str(value)])
        elif flag == 'httpx_threads' and value:
            cmd.extend(["--httpx-threads", str(value)])
        elif flag == 'httpx_retries' and value:
            cmd.extend(["--httpx-retries", str(value)])
        elif flag == 'method' and value:
            cmd.extend(["--method", str(value)])
        elif flag == 'user_agent' and value:
            cmd.extend(["--user-agent", str(value)])
        elif flag == 'headers' and value:
            cmd.extend(["--headers", str(value)])
        elif flag == 'filter_code' and value:
            cmd.extend(["--filter-code", str(value)])
        elif flag == 'filter_length' and value:
            cmd.extend(["--filter-length", str(value)])
        elif flag == 'match_code' and value:
            cmd.extend(["--match-code", str(value)])
        elif flag == 'match_length' and value:
            cmd.extend(["--match-length", str(value)])
        elif flag == 'proxy' and value:
            cmd.extend(["--proxy", str(value)])
        elif flag == 'disable_redirects' and value:
            cmd.append("--disable-redirects")
        elif flag == 'max_redirects' and value:
            cmd.extend(["--max-redirects", str(value)])
        elif flag == 'httpx_json' and value:
            cmd.append("--httpx-json")
        elif flag == 'httpx_csv' and value:
            cmd.append("--httpx-csv")
        
        # NUCLEI flags
        elif flag == 'templates' and value:
            cmd.extend(["-t", str(value)])
        elif flag == 'template_path' and value:
            cmd.extend(["--template-path", str(value)])
        elif flag == 'tags' and value:
            cmd.extend(["--tags", str(value)])
        elif flag == 'severity' and value:
            cmd.extend(["--severity", str(value)])
        elif flag == 'exclude_tags' and value:
            cmd.extend(["--exclude-tags", str(value)])
        elif flag == 'exclude_templates' and value:
            cmd.extend(["--exclude-templates", str(value)])
        elif flag == 'concurrency' and value:
            cmd.extend(["--concurrency", str(value)])
        elif flag == 'nuclei_rate_limit' and value:
            cmd.extend(["--nuclei-rate-limit", str(value)])
        elif flag == 'nuclei_timeout' and value:
            cmd.extend(["--nuclei-timeout", str(value)])
        elif flag == 'nuclei_retries' and value:
            cmd.extend(["--nuclei-retries", str(value)])
        elif flag == 'parallel_processing' and value:
            cmd.extend(["--parallel-processing", str(value)])
        elif flag == 'custom_headers' and value:
            cmd.extend(["--custom-headers", str(value)])
        elif flag == 'nuclei_user_agent' and value:
            cmd.extend(["--nuclei-user-agent", str(value)])
        elif flag == 'vars' and value:
            cmd.extend(["--vars", str(value)])
        elif flag == 'store_resp' and value:
            cmd.append("--store-resp")
        elif flag == 'store_resp_dir' and value:
            cmd.extend(["--store-resp-dir", str(value)])
        elif flag == 'interactsh_server' and value:
            cmd.extend(["--interactsh-server", str(value)])
        elif flag == 'no_interactsh' and value:
            cmd.append("--no-interactsh")
        elif flag == 'interactsh_token' and value:
            cmd.extend(["--interactsh-token", str(value)])
        elif flag == 'nuclei_json' and value:
            cmd.append("--nuclei-json")
        elif flag == 'nuclei_csv' and value:
            cmd.append("--nuclei-csv")
        elif flag == 'markdown_export' and value:
            cmd.extend(["--markdown-export", str(value)])
        elif flag == 'sarif_export' and value:
            cmd.extend(["--sarif-export", str(value)])
      # Enhanced pre-scan information display
    print(f"\n{'='*80}")
    print(f"INITIALIZING {scan_type.upper()} SCAN")
    print(f"{'='*80}")
    print(f"[TARGET]     {target}")
    print(f"[TOOL]       {scan_type}")
    print(f"[TIMESTAMP]  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[COMMAND]    {' '.join(cmd)}")
    print(f"\n[CONFIGURATION]")
    print(f"  Real-time output: ENABLED")
    print(f"  Save to files:    {'ENABLED' if save_output else 'DISABLED'}")
    print(f"  Output format:    {'JSON' if json_output else 'TEXT'}")
    print(f"  Flags selected:   {len(flags)}")
    
    if flags:
        print(f"\n[ACTIVE FLAGS]")
        for flag, value in flags.items():
            if isinstance(value, bool) and value:
                print(f"  + {flag}")
            elif not isinstance(value, bool):
                display_value = str(value)
                if len(display_value) > 50:
                    display_value = display_value[:47] + "..."
                print(f"  + {flag}: {display_value}")
    
    print(f"\n{'='*80}")
    print(f"REAL-TIME SCAN OUTPUT")
    print(f"{'='*80}")
    
    # Initialize variables to avoid scope issues
    process = None
    start_time = time.time()
    
    try:
        # Start the scan process with real-time output streaming
        process = subprocess.Popen(
            cmd, 
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1        )
        
        # Variables to track scan progress
        output_lines = []
        finding_lines = []
        last_activity = time.time()
        findings_count = 0
        
        print(f"\n[SCAN STARTED] {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"[PROCESS ID] {process.pid}")
        print(f"[STATUS] Initializing {scan_type.upper()} scan...")
        print("-" * 80)
        
        # Stream output in real-time
        if process.stdout:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    current_time = datetime.datetime.now().strftime('%H:%M:%S')
                    
                    lower_line = line.lower()

                    # Color-code and categorize output. Only actual nuclei
                    # result lines count as security findings; scanner status
                    # messages such as "No results found" stay informational.
                    if is_security_finding_line(line):
                        findings_count += 1
                        finding_lines.append(line)
                        print(f"[{current_time}] [FIND]  {line}")
                        print(f"[COUNTER] Total security findings: {findings_count}")
                    elif is_informational_finding_line(line):
                        print(f"[{current_time}] [NOTE]  {line}")
                    elif any(keyword in lower_line for keyword in ['warning', 'warn', '[wrn]']):
                        print(f"[{current_time}] [WARN]  {line}")
                    elif any(keyword in lower_line for keyword in ['error', 'failed', 'timeout']):
                        print(f"[{current_time}] [ERROR] {line}")
                    elif any(keyword in lower_line for keyword in ['scanning', 'testing', 'checking']):
                        print(f"[{current_time}] [SCAN]  {line}")
                    else:
                        print(f"[{current_time}] [INFO]  {line}")
                    
                    output_lines.append(line)
                    last_activity = time.time()
        
        # Wait for process to complete
        return_code = process.wait()
        elapsed_total = time.time() - start_time
        
        # Enhanced scan completion summary
        print("-" * 80)
        print(f"[SCAN COMPLETED] {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"[DURATION] {elapsed_total:.2f} seconds ({elapsed_total/60:.1f} minutes)")
        print(f"[OUTPUT LINES] {len(output_lines)} total")
        print(f"[SECURITY FINDINGS] {findings_count} risks detected")
        print(f"[EXIT CODE] {return_code}")
        
        if return_code == 0:
            print(f"[STATUS] SCAN COMPLETED SUCCESSFULLY")
        elif return_code == 2:
            print(f"[STATUS] SCAN COMPLETED WITH SOME ISSUES")
        else:
            print(f"[STATUS] SCAN FAILED OR INTERRUPTED")
        
        # Detailed findings summary
        if findings_count > 0:
            print("\n" + "=" * 80)
            print("SECURITY FINDINGS SUMMARY")
            print("=" * 80)

            for i, finding in enumerate(finding_lines[:10], 1):
                print(f"{i:2d}. {finding}")
            
            if len(finding_lines) > 10:
                print(f"... and {len(finding_lines) - 10} more findings")
            
            print(f"\nTotal findings displayed: {min(len(finding_lines), 10)} of {len(finding_lines)}")
        else:
            print("\n[INFO] No security risks detected in this scan")
        
        # File output information
        if save_output:
            print("\n" + "=" * 80)
            print("OUTPUT FILES")
            print("=" * 80)
            print("[INFO] Results saved to files automatically")
            
            # Find and display the latest results directory
            try:
                result_dirs = [item for item in os.listdir('.') if os.path.isdir(item) and item.startswith('results_')]
                if result_dirs:
                    latest_dir = max(result_dirs, key=lambda x: os.path.getmtime(x))
                    print(f"[DIRECTORY] {latest_dir}")
                    
                    # List key files
                    for filename in ['comprehensive_scan_report.txt', 'security_findings_report.md', 'naabu_results.txt', 'httpx_results.txt', 'nuclei_results.txt']:
                        filepath = os.path.join(latest_dir, filename)
                        if os.path.exists(filepath):
                            file_size = os.path.getsize(filepath)
                            print(f"[FILE] {filename} ({file_size:,} bytes)")
                    
                    print(f"[ACCESS] Use menu option [5] to view detailed results")
            except OSError as e:
                print(f"[ERROR] Could not access results directory: {e}")
        else:
            print("\n[INFO] Output displayed in real-time only (not saved)")
        
        print("=" * 80)
        print(f"\n[SCAN COMPLETED] Press Enter to return to main menu...")
        input()
        return return_code == 0
        
    except KeyboardInterrupt:
        print(f"\n\n{'=' * 80}")
        print("SCAN INTERRUPTED BY USER")
        print("=" * 80)
        if process:
            print("[ACTION] Terminating scan process...")
            try:
                process.terminate()
                process.wait(timeout=5)
                print("[STATUS] Process terminated cleanly")
            except:
                process.kill()
                print("[STATUS] Process forcefully killed")
        
        elapsed = time.time() - start_time
        print(f"[DURATION] Scan ran for {elapsed:.1f} seconds before interruption")
        print("=" * 80)
        return False
        
    except FileNotFoundError:
        print("\n" + "=" * 80)
        print("SCAN ERROR - FILE NOT FOUND")
        print("=" * 80)
        print("[ERROR] workflow.py not found in src/ directory")
        print("[ACTION] Please ensure all toolkit files are present")
        print("[COMMAND] " + " ".join(cmd))
        print("=" * 80)
        return False
        
    except Exception as e:
        print(f"\n{'=' * 80}")
        print("SCAN ERROR - UNEXPECTED FAILURE")
        print("=" * 80)
        print(f"[ERROR] {str(e)}")
        print(f"[COMMAND] {' '.join(cmd)}")
        print(f"[TIME] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        return False


def view_results():
    """View previous scan results."""
    clear_screen()
    print_banner()
    print("PREVIOUS SCAN RESULTS:")
    print("=" * 50)
    
    # Find all result directories
    result_dirs = []
    for item in os.listdir('.'):
        if os.path.isdir(item) and item.startswith('results_'):
            result_dirs.append(item)
    
    if not result_dirs:
        print("No previous scan results found.")
        input("\nPress Enter to continue...")
        return
    
    # Sort by modification time (newest first)
    result_dirs.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Display results
    for i, result_dir in enumerate(result_dirs[:10], 1):  # Show last 10
        stat = os.stat(result_dir)
        mod_time = datetime.datetime.fromtimestamp(stat.st_mtime)
        print(f"  [{i}] {result_dir} - {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\n  [0] Back to main menu")
    
    while True:
        choice = input("\nSelect result to view [0-{}]: ".format(len(result_dirs[:10]))).strip()
        
        if choice == "0":
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(result_dirs[:10]):
                view_result_details(result_dirs[idx])
                return
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

def view_result_details(result_dir):
    """View details of a specific result directory."""
    clear_screen()
    print_banner()
    print(f"SCAN RESULTS: {result_dir}")
    print("=" * 60)
    
    # Look for generated report files
    comprehensive_report = os.path.join(result_dir, "comprehensive_scan_report.txt")
    findings_report = os.path.join(result_dir, "security_findings_report.md")
    
    try:
        if os.path.exists(findings_report):
            print("SECURITY FINDINGS REPORT:")
            print("-" * 40)
            with open(findings_report, 'r', encoding='utf-8', errors='ignore') as f:
                print(f.read())
            print()

        if os.path.exists(comprehensive_report):
            print("COMPREHENSIVE SCAN REPORT:")
            print("-" * 40)
            with open(comprehensive_report, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(content)
        else:
            # Fallback: show directory contents if comprehensive report not found
            print("Directory contents:")
            files = os.listdir(result_dir)
            for file in sorted(files):
                file_path = os.path.join(result_dir, file)
                if os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    print(f"    {file} ({size} bytes)")
                elif os.path.isdir(file_path):
                    print(f"    {file}/")
            
            print("\nNote: No comprehensive_scan_report.txt found.")
            print("This might be an older scan result or incomplete scan.")
        
    except Exception as e:
        print(f"Error reading results: {e}")
    
    input("\nPress Enter to continue...")

def update_templates():
    """Update nuclei templates."""
    clear_screen()
    print_banner()
    print("UPDATING NUCLEI TEMPLATES:")
    print("=" * 50)
    
    try:
        print("Running: nuclei -update-templates")
        result = subprocess.run(["nuclei", "-update-templates"], 
                              timeout=300,  # 5 minute timeout
                              capture_output=False)  # Show output in real-time
        
        if result.returncode == 0:
            print("Templates updated successfully!")
        else:
            print("Template update completed with warnings.")
    
    except subprocess.TimeoutExpired:
        print("Template update timed out after 5 minutes.")
        print("You can try updating manually later: nuclei -update-templates")
    except FileNotFoundError:
        print("nuclei command not found. Please ensure it's installed and in PATH.")
        print("Try: export PATH=$PATH:/usr/local/bin")
    except Exception as e:
        print(f"Template update failed: {e}")
    
    input("\nPress Enter to continue...")

def show_help():
    """Show help and documentation."""
    clear_screen()
    print_banner()
    print("HELP & DOCUMENTATION:")
    print("=" * 50)
    print()
    print("TOOL DESCRIPTIONS:")
    print("  • naabu   - Fast port scanner for network reconnaissance")
    print("  • httpx   - HTTP toolkit for service discovery and analysis")
    print("  • nuclei  - Vulnerability scanner with 5000+ templates")
    print()
    print("SCAN TYPES:")
    print("  • Port Scan      - Discover open ports on target")
    print("  • HTTP Detection - Find HTTP services and gather info")
    print("  • Vuln Scan      - Check for known vulnerabilities")
    print()
    print("OPTIONS:")
    print("  • Stealth Mode   - Slower, more discreet scanning")
    print("  • Save Output    - Save results to files")
    print("  • JSON Output    - Machine-readable output format")
    print()
    print("DOCUMENTATION:")
    print("  • README.md      - General overview and quick start")
    print("  • docs/USAGE.md  - Detailed usage examples")
    print("  • docs/INSTALL.md - Installation instructions")
    print()
    print("GETTING STARTED:")
    print("  • Run: python mtscan.py")
    print("  • Or: python src/workflow.py --all -host <target>")
    print()
    print("EXAMPLES:")
    print("  Target formats:")
    print("    • 192.168.1.100")
    print("    • example.com")
    print("    • https://target.com")
    print()
    
    input("Press Enter to continue...")


PROJECTDISCOVERY_GO_MODULES = {
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


def expose_updated_tool(tool, source_path):
    """Expose a Go-installed scanner through /usr/local/bin when possible."""
    target_name = "httpx-toolkit" if tool == "httpx" else tool
    target_path = f"/usr/local/bin/{target_name}"

    try:
        if os.path.lexists(target_path):
            os.remove(target_path)
        os.symlink(source_path, target_path)
        print(f"[OK] {tool} exposed at {target_path}")
        return True
    except PermissionError:
        print(f"[INFO] Need sudo to update {target_path}")
    except OSError as exc:
        print(f"[WARN] Could not update {target_path}: {exc}")

    try:
        result = subprocess.run(
            ["sudo", "ln", "-sfn", source_path, target_path],
            check=False,
            timeout=30,
        )
        if result.returncode == 0:
            print(f"[OK] {tool} exposed at {target_path}")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        print(f"[WARN] sudo link failed for {tool}: {exc}")

    print(f"[ACTION] Add Go bin to PATH if needed: export PATH=$PATH:$(go env GOPATH)/bin")
    return False


def stop_process_tree(process):
    """Terminate a process and its children so timeout retries cannot hang."""
    if process.poll() is not None:
        return

    try:
        if platform.system().lower() == "linux":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if platform.system().lower() == "linux":
                os.killpg(process.pid, signal.SIGKILL)
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


def run_timed_command(cmd, timeout_seconds, env=None, capture_output=True, passthrough=False):
    """Run a command with process-group timeout protection."""
    process = subprocess.Popen(
        cmd,
        stdout=None if passthrough else (subprocess.PIPE if capture_output else subprocess.DEVNULL),
        stderr=None if passthrough else subprocess.PIPE,
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


def prepare_go_build_env():
    """Prepare Go build environment using disk-backed temp/cache directories."""
    env = os.environ.copy()
    try:
        gopath = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except Exception:
        gopath = os.path.expanduser("~/go")

    build_root = os.path.join(gopath, "mtscan-build")
    tmp_dir = os.path.join(build_root, "tmp")
    cache_dir = os.path.join(build_root, "cache")
    mod_cache_dir = os.path.join(build_root, "pkg", "mod")

    for directory in (tmp_dir, cache_dir, mod_cache_dir):
        os.makedirs(directory, exist_ok=True)

    env["TMPDIR"] = tmp_dir
    env["GOTMPDIR"] = tmp_dir
    env["GOCACHE"] = cache_dir
    env["GOMODCACHE"] = mod_cache_dir
    env["CGO_ENABLED"] = "1"
    env["GO111MODULE"] = "on"
    env["GOPROXY"] = "https://proxy.golang.org,direct"

    print(f"[INFO] Go build temp/cache: {build_root}")
    return env


def update_projectdiscovery_tool(tool, module):
    """Install or update one ProjectDiscovery scanner to the latest Go release."""
    if shutil.which("go") is None:
        print("[ERROR] Go is required to update scanner tools.")
        return False

    print(f"\n[UPDATE] {tool}: {module}")
    env = prepare_go_build_env()

    returncode, stdout, stderr, timed_out = run_timed_command(
        ["go", "install", "-v", "-trimpath", module],
        900,
        env=env,
        capture_output=True,
    )
    if timed_out:
        print(f"[ERROR] {tool} update timed out after 15 minutes.")
        return False

    if returncode != 0:
        print(f"[ERROR] {tool} update failed with exit code {returncode}.")
        if stdout:
            print(stdout[-1000:])
        if stderr:
            print(stderr[-1000:])
        return False

    try:
        gopath = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except Exception as exc:
        print(f"[WARN] Could not locate GOPATH after updating {tool}: {exc}")
        return True

    binary_path = os.path.join(gopath, "bin", tool)
    if os.path.exists(binary_path):
        expose_updated_tool(tool, binary_path)
        print(f"[OK] {tool} updated at {binary_path}")
        return True

    print(f"[WARN] {tool} update completed, but binary was not found at {binary_path}")
    return False


def update_scanner_tools():
    """Update scanner binaries and nuclei templates without rerunning full setup."""
    print("\nUPDATING PROJECTDISCOVERY TOOLS TO LATEST:")
    print("=" * 50)

    success_count = 0
    for tool, module in PROJECTDISCOVERY_GO_MODULES.items():
        if update_projectdiscovery_tool(tool, module):
            success_count += 1

    nuclei_path = find_tool_path("nuclei") or "nuclei"
    print("\n[UPDATE] nuclei templates")
    try:
        result = subprocess.run([nuclei_path, "-update-templates"], timeout=300, check=False)
        if result.returncode == 0:
            print("[OK] Nuclei templates updated.")
        else:
            print("[WARN] Nuclei template update completed with warnings.")
    except subprocess.TimeoutExpired:
        print("[WARN] Nuclei template update timed out after 5 minutes.")
    except FileNotFoundError:
        print("[WARN] nuclei not found for template update.")

    print(f"\n[SUMMARY] Updated {success_count}/3 scanner binaries.")
    return success_count == 3


def install_tools():
    """Run the installation script."""
    clear_screen()
    print_banner()
    print("INSTALLING/UPDATING TOOLS:")
    print("=" * 50)
    print("  [1] Update scanner binaries to latest")
    print("      Runs go install @latest for naabu, httpx, and nuclei")
    print("  [2] Run full setup installer")
    print("      Installs system packages, Go, scanner tools, and config")
    print()

    install_choice = input("Select option [1-2]: ").strip() or "1"

    if install_choice == "1":
        update_scanner_tools()
        input("\nPress Enter to continue...")
        return
    if install_choice != "2":
        print("Invalid option.")
        input("\nPress Enter to continue...")
        return
    
    if not os.path.exists("install/setup.py"):
        print("Installation script not found at install/setup.py")
        print("Expected structure:")
        print("  ./install/setup.py")
        input("\nPress Enter to continue...")
        return
    
    try:
        print("Running installation script...")
        returncode, _, _, timed_out = run_timed_command(
            ["python3", "install/setup.py"],
            1800,
            passthrough=True,
        )
        if timed_out:
            print("Installation timed out after 30 minutes. Process tree was stopped.")
        elif returncode != 0:
            print("Installation did not complete without sudo; trying with sudo...")
            returncode, _, _, timed_out = run_timed_command(
                ["sudo", "python3", "install/setup.py"],
                1800,
                passthrough=True,
            )
            if timed_out:
                print("Installation timed out after 30 minutes. Process tree was stopped.")
        
        if returncode == 0 and not timed_out:
            print("Installation completed successfully!")
        else:
            print("Installation completed with some issues.")
        
    except Exception as e:
        print(f"Installation failed: {e}")
    
    input("\nPress Enter to continue...")

def get_naabu_flags():
    """Interactive flag selection for naabu with single-flag selection system."""
    print("\n" + "="*60)
    print("NAABU PORT SCANNER - FLAG CONFIGURATION")
    print("="*60)
    print("Select scanning parameters one by one. Enter -0 when finished.")
    print("Enter -1 to see the menu again after selecting a flag.")
    print()
    
    selected_flags = {}
    
    while True:
        print("\nNAABU FLAGS (Single selection - choose one):")
        print("  -p  | Ports to scan (e.g., '80,443,8080' or 'top-1000')")
        print("  -s  | Stealth mode (reduces rate and uses SYN scan)")
        print("  -t  | Threads/Concurrency (default: 25)")
        print("  -r  | Rate limit (packets per second)")
        print("  -e  | Exclude specific ports")
        print("  -T  | Timeout per port (milliseconds)")
        print("  -R  | Retries for failed ports")
        print("  -S  | Scan type (syn/connect)")
        print("  -I  | Network interface to use")
        print("  -P  | Source port for scanning")
        print("  -H  | Host discovery mode")
        print("  -n  | Skip ping discovery (no ping)")
        print("  -v  | Verbose output")
        print("  -j  | JSON output format")
        print("  -c  | CSV output format")
        print("  -d  | Debug mode")
        print("  -0  | FINISH flag selection")
        print("  -1  | Show this menu again")
        
        if selected_flags:
            print(f"\nCurrently selected: {', '.join(selected_flags.keys())}")
        
        choice = input("\nSelect flag: ").strip()
        
        if choice == "-0":
            break
        elif choice == "-1":
            continue
        elif choice == "-p":
            print("\nPort Selection Options:")
            print("  1. Specific ports (e.g., 80,443,8080)")
            print("  2. Port range (e.g., 1000-2000)")
            print("  3. Top ports (e.g., top-100, top-1000)")
            print("  4. All ports (1-65535)")
            port_choice = input("Choose option (1-4): ").strip()
            
            if port_choice == "1":
                ports = input("Enter specific ports (comma-separated): ").strip()
                if ports:
                    selected_flags['ports'] = ports
                    print(f"Selected ports: {ports}")
            elif port_choice == "2":
                start_port = input("Start port: ").strip()
                end_port = input("End port: ").strip()
                if start_port and end_port:
                    try:
                        if 1 <= int(start_port) <= int(end_port) <= 65535:
                            selected_flags['ports'] = f"{start_port}-{end_port}"
                            print(f"Selected port range: {start_port}-{end_port}")
                        else:
                            print("ERROR: Invalid port range")
                    except ValueError:
                        print("ERROR: Ports must be numbers")
            elif port_choice == "3":
                top_ports = input("Enter number (e.g., 100, 1000): ").strip()
                if top_ports:
                    selected_flags['ports'] = f"top-{top_ports}"
                    print(f"Selected top {top_ports} ports")
            elif port_choice == "4":
                selected_flags['ports'] = "1-65535"
                print("Selected all ports (1-65535)")
                
        elif choice == "-s":
            selected_flags['stealth'] = True
            print("STEALTH MODE enabled:")
            print("  - Reduced scan rate (10 packets/sec)")
            print("  - SYN scan type for minimal footprint")
            print("  - Lower thread count (25)")
            print("  - Single retry attempt")
            
        elif choice == "-t":
            threads = input("Enter thread count (1-100, default 25): ").strip()
            if threads:
                try:
                    thread_count = int(threads)
                    if 1 <= thread_count <= 100:
                        selected_flags['threads'] = thread_count
                        print(f"Threads set to: {thread_count}")
                    else:
                        print("ERROR: Threads must be between 1-100")
                except ValueError:
                    print("ERROR: Thread count must be a number")
                    
        elif choice == "-r":
            rate = input("Enter rate limit (packets/sec, default 1000): ").strip()
            if rate:
                try:
                    rate_limit = int(rate)
                    if 1 <= rate_limit <= 10000:
                        selected_flags['rate'] = rate_limit
                        print(f"Rate limit set to: {rate_limit} packets/sec")
                    else:
                        print("ERROR: Rate must be between 1-10000")
                except ValueError:
                    print("ERROR: Rate must be a number")
                    
        elif choice == "-e":
            exclude = input("Enter ports to exclude (comma-separated): ").strip()
            if exclude:
                selected_flags['exclude_ports'] = exclude
                print(f"Excluding ports: {exclude}")
                
        elif choice == "-T":
            timeout = input("Enter timeout in milliseconds (default 5000): ").strip()
            if timeout:
                try:
                    timeout_ms = int(timeout)
                    if 100 <= timeout_ms <= 30000:
                        selected_flags['naabu_timeout'] = timeout_ms
                        print(f"Timeout set to: {timeout_ms}ms")
                    else:
                        print("ERROR: Timeout must be between 100-30000ms")
                except ValueError:
                    print("ERROR: Timeout must be a number")
        elif choice == "-R":
            retries = input("Enter retry count (0-5, default 2): ").strip()
            if retries:
                try:
                    retry_count = int(retries)
                    if 0 <= retry_count <= 5:
                        selected_flags['naabu_retries'] = retry_count
                        print(f"Retries set to: {retry_count}")
                    else:
                        print("ERROR: Retries must be between 0-5")
                except ValueError:
                    print("ERROR: Retries must be a number")
                    
        elif choice == "-S":
            print("Scan type options:")
            print("  1. SYN scan (faster, requires root)")
            print("  2. Connect scan (compatible, no root needed)")
            scan_choice = input("Choose scan type (1-2): ").strip()
            if scan_choice == "1":
                selected_flags['scan_type'] = 'syn'
                print("Selected SYN scan (requires root privileges)")
            elif scan_choice == "2":
                selected_flags['scan_type'] = 'connect'
                print("Selected Connect scan (no root required)")
                
        elif choice == "-I":
            interface = input("Enter network interface (e.g., eth0, wlan0): ").strip()
            if interface:
                selected_flags['interface'] = interface
                print(f"Interface set to: {interface}")
                
        elif choice == "-P":
            source_port = input("Enter source port (1-65535): ").strip()
            if source_port:
                try:
                    port_num = int(source_port)
                    if 1 <= port_num <= 65535:
                        selected_flags['source_port'] = port_num
                        print(f"Source port set to: {port_num}")
                    else:
                        print("ERROR: Port must be between 1-65535")
                except ValueError:
                    print("ERROR: Port must be a number")
                    
        elif choice == "-H":
            selected_flags['host_discovery'] = True
            print("Host discovery enabled")
            
        elif choice == "-n":
            selected_flags['no_ping'] = True
            print("Ping discovery disabled")
            
        elif choice == "-v":
            selected_flags['naabu_verbose'] = True
            print("Verbose output enabled")
            
        elif choice == "-j":
            selected_flags['naabu_json'] = True
            print("JSON output format enabled")
            
        elif choice == "-c":
            selected_flags['naabu_csv'] = True
            print("CSV output format enabled")
            
        elif choice == "-d":
            selected_flags['naabu_debug'] = True
            print("Debug mode enabled")
            
        else:
            print("ERROR: Invalid option. Use -0 to finish, -1 to see menu.")
    
    print(f"\nNaabu configuration completed with {len(selected_flags)} flags selected.")
    return selected_flags

def get_httpx_flags():
    """Interactive flag selection for httpx with single-flag selection system."""
    print("\n" + "="*60)
    print("HTTPX HTTP SERVICE DETECTION - FLAG CONFIGURATION")
    print("="*60)
    print("Select HTTP analysis parameters one by one. Enter -0 when finished.")
    print("Enter -1 to see the menu again after selecting a flag.")
    print()
    
    selected_flags = {}
    
    while True:
        print("\nHTTPX FLAGS (Single selection - choose one):")
        print("  -t  | Title extraction")
        print("  -s  | Status code display (uses -status-code flag)")
        print("  -T  | Technology detection")
        print("  -w  | Web server information")
        print("  -f  | Follow HTTP redirects")
        print("  -r  | Rate limit (requests per second)")
        print("  -c  | Content length display")
        print("  -R  | Response time measurement")
        print("  -M  | HTTP method (GET, POST, etc.)")
        print("  -U  | Custom User-Agent string")
        print("  -H  | Custom HTTP headers")
        print("  -F  | Filter by status codes")
        print("  -L  | Filter by content length")
        print("  -m  | Match specific status codes")
        print("  -l  | Match specific content lengths")
        print("  -p  | HTTP proxy configuration")
        print("  -d  | Disable redirects")
        print("  -x  | Maximum redirects")
        print("  -j  | JSON output format")
        print("  -v  | CSV output format")
        print("  -0  | FINISH flag selection")
        print("  -1  | Show this menu again")
        
        if selected_flags:
            print(f"\nCurrently selected: {', '.join(selected_flags.keys())}")
        
        choice = input("\nSelect flag: ").strip()
        
        if choice == "-0":
            break
        elif choice == "-1":
            continue
        elif choice == "-t":
            selected_flags['title'] = True
            print("Title extraction enabled")
        elif choice == "-s":
            selected_flags['status_code'] = True
            print("Status code display enabled")
        elif choice == "-T":
            selected_flags['tech_detect'] = True
            print("Technology detection enabled")
        elif choice == "-w":
            selected_flags['web_server'] = True
            print("Web server information enabled")
        elif choice == "-f":
            selected_flags['follow_redirects'] = True
            print("Follow redirects enabled")
        elif choice == "-r":
            rate = input("Enter rate limit (requests/sec, default 150): ").strip()
            if rate:
                try:
                    rate_limit = int(rate)
                    if 1 <= rate_limit <= 1000:
                        selected_flags['rate_limit'] = rate_limit
                        print(f"Rate limit set to: {rate_limit} req/sec")
                    else:
                        print("ERROR: Rate must be between 1-1000")
                except ValueError:
                    print("ERROR: Rate must be a number")
        elif choice == "-c":
            selected_flags['content_length'] = True
            print("Content length display enabled")
        elif choice == "-R":
            selected_flags['response_time'] = True
            print("Response time measurement enabled")
        elif choice == "-M":
            method = input("Enter HTTP method (GET, POST, PUT, etc.): ").strip().upper()
            if method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                selected_flags['method'] = method
                print(f"HTTP method set to: {method}")
            else:
                print("ERROR: Invalid HTTP method")
        elif choice == "-U":
            user_agent = input("Enter User-Agent string: ").strip()
            if user_agent:
                selected_flags['user_agent'] = user_agent
                print(f"User-Agent set to: {user_agent}")
        elif choice == "-H":
            headers = input("Enter headers (comma-separated, e.g., 'X-API-Key: value,Accept: application/json'): ").strip()
            if headers:
                selected_flags['headers'] = headers
                print(f"Custom headers set: {headers}")
        elif choice == "-F":
            filter_codes = input("Enter status codes to filter (comma-separated, e.g., 404,500): ").strip()
            if filter_codes:
                selected_flags['filter_code'] = filter_codes
                print(f"Filter codes set: {filter_codes}")
        elif choice == "-L":
            filter_length = input("Enter content lengths to filter (comma-separated): ").strip()
            if filter_length:
                selected_flags['filter_length'] = filter_length
                print(f"Filter lengths set: {filter_length}")
        elif choice == "-m":
            match_codes = input("Enter status codes to match (comma-separated): ").strip()
            if match_codes:
                selected_flags['match_code'] = match_codes
                print(f"Match codes set: {match_codes}")
        elif choice == "-l":
            match_length = input("Enter content lengths to match (comma-separated): ").strip()
            if match_length:
                selected_flags['match_length'] = match_length
                print(f"Match lengths set: {match_length}")
        elif choice == "-p":
            proxy = input("Enter proxy URL (e.g., http://127.0.0.1:8080): ").strip()
            if proxy:
                selected_flags['proxy'] = proxy
                print(f"Proxy set to: {proxy}")
        elif choice == "-d":
            selected_flags['disable_redirects'] = True
            print("HTTP redirects disabled")
        elif choice == "-x":
            max_redirects = input("Enter maximum redirects (default 10): ").strip()
            if max_redirects:
                try:
                    max_redir = int(max_redirects)
                    if 0 <= max_redir <= 20:
                        selected_flags['max_redirects'] = max_redir
                        print(f"Maximum redirects set to: {max_redir}")
                    else:
                        print("ERROR: Max redirects must be between 0-20")
                except ValueError:
                    print("ERROR: Max redirects must be a number")
        elif choice == "-j":
            selected_flags['httpx_json'] = True
            print("JSON output format enabled")
        elif choice == "-v":
            selected_flags['httpx_csv'] = True
            print("CSV output format enabled")
        else:
            print("ERROR: Invalid option. Use -0 to finish, -1 to see menu.")
    
    print(f"\nHTTPX configuration completed with {len(selected_flags)} flags selected.")
    return selected_flags

def get_nuclei_flags():
    """Interactive flag selection for nuclei with single-flag selection system."""
    print("\n" + "="*60)
    print("NUCLEI VULNERABILITY SCANNER - FLAG CONFIGURATION")
    print("="*60)
    print("Select vulnerability scanning parameters one by one. Enter -0 when finished.")
    print("Enter -1 to see the menu again after selecting a flag.")
    print()
    
    selected_flags = {}
    
    while True:
        print("\nNUCLEI FLAGS (Single selection - choose one):")
        print("  -t  | Custom templates/template directory")
        print("  -T  | Template tags (e.g., cve, rce, sqli)")
        print("  -s  | Severity filter (critical, high, medium, low)")
        print("  -e  | Exclude tags")
        print("  -E  | Exclude templates")
        print("  -c  | Concurrency/parallel templates")
        print("  -r  | Rate limit (requests per second)")
        print("  -R  | Timeout for requests")
        print("  -x  | Number of retries")
        print("  -b  | Bulk size for parallel processing")
        print("  -p  | HTTP proxy")
        print("  -H  | Custom headers")
        print("  -U  | Custom User-Agent")
        print("  -v  | Custom variables")
        print("  -S  | Store HTTP responses")
        print("  -d  | Store response directory")
        print("  -i  | Interactsh server URL")
        print("  -I  | Disable Interactsh")
        print("  -k  | Interactsh token")
        print("  -D  | Disable HTTP redirects")
        print("  -m  | Maximum redirects")
        print("  -j  | JSON output format")
        print("  -C  | CSV output format")
        print("  -M  | Markdown export")
        print("  -F  | SARIF export")
        print("  -0  | FINISH flag selection")
        print("  -1  | Show this menu again")
        
        if selected_flags:
            print(f"\nCurrently selected: {', '.join(selected_flags.keys())}")
        
        choice = input("\nSelect flag: ").strip()
        
        if choice == "-0":
            break
        elif choice == "-1":
            continue
        elif choice == "-t":
            print("Template options:")
            print("  1. Specific template file")
            print("  2. Template directory")
            print("  3. Built-in template (e.g., cves/, technologies/)")
            template_choice = input("Choose option (1-3): ").strip()
            
            if template_choice == "1":
                template_file = input("Enter template file path: ").strip()
                if template_file:
                    selected_flags['templates'] = template_file
                    print(f"Template file set: {template_file}")
            elif template_choice == "2":
                template_dir = input("Enter template directory path: ").strip()
                if template_dir:
                    selected_flags['template_path'] = template_dir
                    print(f"Template directory set: {template_dir}")
            elif template_choice == "3":
                built_in = input("Enter built-in template path (e.g., cves/, technologies/): ").strip()
                if built_in:
                    selected_flags['templates'] = built_in
                    print(f"Built-in template set: {built_in}")
                    
        elif choice == "-T":
            print("Common tags:")
            print("  cve, rce, sqli, xss, lfi, rfi, ssrf, xxe")
            print("  auth-bypass, exposure, misconfiguration")
            tags = input("Enter tags (comma-separated): ").strip()
            if tags:
                selected_flags['tags'] = tags
                print(f"Tags set: {tags}")
                
        elif choice == "-s":
            print("Severity levels:")
            print("  1. critical")
            print("  2. high") 
            print("  3. medium")
            print("  4. low")
            print("  5. critical,high")
            print("  6. critical,high,medium")
            print("  7. all (critical,high,medium,low)")
            severity_choice = input("Choose severity (1-7): ").strip()
            
            severity_map = {
                "1": "critical",
                "2": "high", 
                "3": "medium",
                "4": "low",
                "5": "critical,high",
                "6": "critical,high,medium",
                "7": "critical,high,medium,low"
            }
            
            if severity_choice in severity_map:
                selected_flags['severity'] = severity_map[severity_choice]
                print(f"Severity filter set: {severity_map[severity_choice]}")
            else:
                custom_severity = input("Enter custom severity (comma-separated): ").strip()
                if custom_severity:
                    selected_flags['severity'] = custom_severity
                    print(f"Custom severity set: {custom_severity}")
                    
        elif choice == "-e":
            exclude_tags = input("Enter tags to exclude (comma-separated): ").strip()
            if exclude_tags:
                selected_flags['exclude_tags'] = exclude_tags
                print(f"Exclude tags set: {exclude_tags}")
                
        elif choice == "-E":
            exclude_templates = input("Enter templates to exclude: ").strip()
            if exclude_templates:
                selected_flags['exclude_templates'] = exclude_templates
                print(f"Exclude templates set: {exclude_templates}")
                
        elif choice == "-c":
            concurrency = input("Enter concurrency (1-50, default 10): ").strip()
            if concurrency:
                try:
                    conc_val = int(concurrency)
                    if 1 <= conc_val <= 50:
                        selected_flags['concurrency'] = conc_val
                        print(f"Concurrency set to: {conc_val}")
                    else:
                        print("ERROR: Concurrency must be between 1-50")
                except ValueError:
                    print("ERROR: Concurrency must be a number")
                    
        elif choice == "-r":
            rate = input("Enter rate limit (req/sec, default 50): ").strip()
            if rate:
                try:
                    rate_limit = int(rate)
                    if 1 <= rate_limit <= 500:
                        selected_flags['nuclei_rate_limit'] = rate_limit
                        print(f"Rate limit set to: {rate_limit} req/sec")
                    else:
                        print("ERROR: Rate must be between 1-500")
                except ValueError:
                    print("ERROR: Rate must be a number")
                    
        elif choice == "-R":
            timeout = input("Enter timeout in seconds (default 10): ").strip()
            if timeout:
                try:
                    timeout_val = int(timeout)
                    if 1 <= timeout_val <= 60:
                        selected_flags['nuclei_timeout'] = timeout_val
                        print(f"Timeout set to: {timeout_val}s")
                    else:
                        print("ERROR: Timeout must be between 1-60 seconds")
                except ValueError:
                    print("ERROR: Timeout must be a number")
                    
        elif choice == "-x":
            retries = input("Enter retry count (0-5, default 2): ").strip()
            if retries:
                try:
                    retry_count = int(retries)
                    if 0 <= retry_count <= 5:
                        selected_flags['nuclei_retries'] = retry_count
                        print(f"Retries set to: {retry_count}")
                    else:
                        print("ERROR: Retries must be between 0-5")
                except ValueError:
                    print("ERROR: Retries must be a number")
                    
        elif choice == "-b":
            bulk_size = input("Enter bulk size (1-50, default 10): ").strip()
            if bulk_size:
                try:
                    bulk_val = int(bulk_size)
                    if 1 <= bulk_val <= 50:
                        selected_flags['parallel_processing'] = bulk_val
                        print(f"Bulk size set to: {bulk_val}")
                    else:
                        print("ERROR: Bulk size must be between 1-50")
                except ValueError:
                    print("ERROR: Bulk size must be a number")
                    
        elif choice == "-p":
            proxy = input("Enter proxy URL (e.g., http://127.0.0.1:8080): ").strip()
            if proxy:
                selected_flags['proxy'] = proxy
                print(f"Proxy set to: {proxy}")
                
        elif choice == "-H":
            headers = input("Enter custom headers (comma-separated): ").strip()
            if headers:
                selected_flags['custom_headers'] = headers
                print(f"Custom headers set: {headers}")
                
        elif choice == "-U":
            user_agent = input("Enter User-Agent string: ").strip()
            if user_agent:
                selected_flags['nuclei_user_agent'] = user_agent
                print(f"User-Agent set: {user_agent}")
                
        elif choice == "-v":
            variables = input("Enter custom variables (key=value format): ").strip()
            if variables:
                selected_flags['vars'] = variables
                print(f"Variables set: {variables}")
                
        elif choice == "-S":
            selected_flags['store_resp'] = True
            print("HTTP response storage enabled")
            
        elif choice == "-d":
            resp_dir = input("Enter response storage directory: ").strip()
            if resp_dir:
                selected_flags['store_resp_dir'] = resp_dir
                print(f"Response directory set: {resp_dir}")
                
        elif choice == "-i":
            interactsh_server = input("Enter Interactsh server URL: ").strip()
            if interactsh_server:
                selected_flags['interactsh_server'] = interactsh_server
                print(f"Interactsh server set: {interactsh_server}")
                
        elif choice == "-I":
            selected_flags['no_interactsh'] = True
            print("Interactsh disabled")
            
        elif choice == "-k":
            interactsh_token = input("Enter Interactsh token: ").strip()
            if interactsh_token:
                selected_flags['interactsh_token'] = interactsh_token
                print("Interactsh token configured")
                
        elif choice == "-D":
            selected_flags['disable_redirects'] = True
            print("HTTP redirects disabled")
            
        elif choice == "-m":
            max_redirects = input("Enter maximum redirects (default 10): ").strip()
            if max_redirects:
                try:
                    max_redir = int(max_redirects)
                    if 0 <= max_redir <= 20:
                        selected_flags['max_redirects'] = max_redir
                        print(f"Maximum redirects set to: {max_redir}")
                    else:
                        print("ERROR: Max redirects must be between 0-20")
                except ValueError:
                    print("ERROR: Max redirects must be a number")
                
        elif choice == "-j":
            selected_flags['nuclei_json'] = True
            print("JSON output format enabled")
            
        elif choice == "-C":
            selected_flags['nuclei_csv'] = True
            print("CSV output format enabled")
            
        elif choice == "-M":
            markdown_file = input("Enter Markdown export file path: ").strip()
            if markdown_file:
                selected_flags['markdown_export'] = markdown_file
                print(f"Markdown export set: {markdown_file}")
                
        elif choice == "-F":
            sarif_file = input("Enter SARIF export file path: ").strip()
            if sarif_file:
                selected_flags['sarif_export'] = sarif_file
                print(f"SARIF export set: {sarif_file}")
                
        else:
            print("ERROR: Invalid option. Use -0 to finish, -1 to see menu.")
    
    print(f"\nNuclei configuration completed with {len(selected_flags)} flags selected.")
    return selected_flags

def explain_scan_modes():
    """Explain the difference between Silent and Stealth modes clearly."""
    print("\n" + "="*70)
    print("SCAN MODE EXPLANATIONS")
    print("="*70)
    print()
    print("SILENT MODE:")
    print("  - Controls OUTPUT DISPLAY only")
    print("  - Tools run with minimal console output") 
    print("  - Reduces screen clutter and noise")
    print("  - Does NOT affect network behavior")
    print("  - Scan speed and intensity remain normal")
    print("  - Used for cleaner logs and automated scripts")
    print()
    print("STEALTH MODE:")
    print("  - Controls NETWORK BEHAVIOR")
    print("  - Reduces scan intensity and speed")
    print("  - Uses lower packet rates and connection limits")
    print("  - Aims to avoid detection by security systems")
    print("  - May take significantly longer to complete")
    print("  - Minimizes network footprint and signatures")
    print()
    print("KEY DIFFERENCES:")
    print("  Silent = Quiet output, normal scanning")
    print("  Stealth = Discreet scanning, normal output")
    print()
    print("RECOMMENDATION:")
    print("  - Use STEALTH for production targets")
    print("  - Use SILENT for cleaner logs/automation")
    print("  - Both can be used together if needed")
    print("="*70)

def validate_target_input(target):
    """Validate target input with comprehensive checks."""
    if not target or target.isspace():
        return False, "Target cannot be empty or whitespace only"
    
    target = target.strip()
    
    # Handle URLs by extracting the domain/IP
    if target.startswith(('http://', 'https://')):
        try:
            parsed = urllib.parse.urlparse(target)
            target = parsed.hostname or parsed.netloc
            if not target:
                return False, "Could not extract hostname from URL"
        except Exception:
            return False, "Invalid URL format"
    
    # Check for localhost variants
    if target.lower() in ['localhost', 'local']:
        return True, '127.0.0.1'
    
    # Try to validate as IP address
    try:
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private:
            print(f"NOTE: {target} is a private IP address")
        elif ip_obj.is_loopback:
            print(f"NOTE: {target} is a loopback address")
        elif ip_obj.is_link_local:
            print(f"NOTE: {target} is a link-local address")
        return True, str(ip_obj)
    except ValueError:
        pass
    
    # Validate as domain name
    # Basic domain validation
    if len(target) > 255:
        return False, "Domain name too long (max 255 characters)"
    
    if target.endswith('.'):
        target = target[:-1]  # Strip trailing dot
    
    # Check for invalid characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', target):
        return False, "Domain contains invalid characters"
    
    # Check domain parts
    parts = target.split('.')
    if len(parts) < 2:
        return False, "Domain must have at least one dot (e.g., example.com)"
    
    for part in parts:
        if not part:
            return False, "Domain cannot have empty parts (double dots)"
        if len(part) > 63:
            return False, "Domain part too long (max 63 characters per part)"
        if part.startswith('-') or part.endswith('-'):
            return False, "Domain parts cannot start or end with hyphens"
    
    # Check TLD
    if len(parts[-1]) < 2:
        return False, "Top-level domain too short"
    
    return True, target

def get_safe_scan_confirmation(target, scan_type):
    """Get user confirmation with legal notice."""
    print("\n" + "!"*60)
    print("LEGAL NOTICE AND AUTHORIZATION REQUIRED")
    print("!"*60)
    print()
    print("You are about to perform a security scan on:")
    print(f"  TARGET: {target}")
    print(f"  SCAN TYPE: {scan_type}")
    print()
    print("IMPORTANT LEGAL REQUIREMENTS:")
    print("  1. You must OWN the target system, OR")
    print("  2. Have EXPLICIT written permission to scan it")
    print("  3. Unauthorized scanning may violate laws")
    print("  4. You are responsible for compliance with local laws")
    print()
    print("CONFIRM AUTHORIZATION:")
    
    while True:
        confirm = input("Do you have authorization to scan this target? [y/N]: ").strip().lower()
        if confirm in ['y', 'yes']:
            print("Authorization confirmed. Proceeding with scan...")
            return True
        elif confirm in ['n', 'no', '']:
            print("Scan cancelled. Authorization is required.")
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def show_scan_type_help(scan_type):
    """Show detailed help for each scan type."""
    print(f"\n{'='*60}")
    print(f"HELP: {scan_type.upper()} SCAN")
    print("="*60)
    
    if scan_type == "naabu":
        print("NAABU PORT SCANNER:")
        print("  Purpose: Discover open ports and services")
        print("  Speed: Fast (can scan 65K ports in seconds)")
        print("  Output: List of open ports with optional service info")
        print("  Best for: Initial reconnaissance, service discovery")
        print()
        print("COMMON USE CASES:")
        print("  - Find web servers (ports 80, 443, 8080, etc.)")
        print("  - Discover SSH servers (port 22)")
        print("  - Identify database services (3306, 5432, 1433)")
        print("  - Locate admin interfaces on uncommon ports")
        
    elif scan_type == "httpx":
        print("HTTPX HTTP SERVICE DETECTION:")
        print("  Purpose: Analyze HTTP/HTTPS services")
        print("  Speed: Medium (depends on number of services)")
        print("  Output: Web server info, titles, technologies")
        print("  Best for: Web application enumeration")
        print()
        print("COMMON USE CASES:")
        print("  - Identify web applications and technologies")
        print("  - Extract page titles for quick assessment")
        print("  - Discover server types (Apache, Nginx, IIS)")
        print("  - Find hidden or unusual web services")
        
    elif scan_type == "nuclei":
        print("NUCLEI VULNERABILITY SCANNER:")
        print("  Purpose: Detect security vulnerabilities")
        print("  Speed: Slow (thorough security testing)")
        print("  Output: Detailed vulnerability reports")
        print("  Best for: Security assessment, CVE detection")
        print()
        print("COMMON USE CASES:")
        print("  - Find known CVEs and security issues")
        print("  - Detect misconfigurations")
        print("  - Identify exposed sensitive files")
        print("  - Test for common web vulnerabilities")
    
    print("="*60)

def main():
    """Main menu loop."""
    while True:
        clear_screen()
        print_banner()
        print_tools_status()
        print_main_menu()
        
        choice = input("Select option [0-9]: ").strip()
        
        if choice == "0":
            print("\nGoodbye!")
            break
        elif choice == "1":
            # Port Scan (naabu)
            target = get_target_input()
            if target:
                run_scan("naabu", target)
        elif choice == "2":
            # HTTP Service Detection (httpx)
            target = get_target_input()
            if target:
                run_scan("httpx", target)
        elif choice == "3":
            # Vulnerability Scan (nuclei)
            target = get_target_input()
            if target:
                run_scan("nuclei", target)
        elif choice == "4":
            # Complete scan chain
            target = get_target_input()
            if target:
                run_scan("all", target)
        elif choice == "5":
            view_results()
        elif choice == "6":
            update_templates()
        elif choice == "7":
            print("\nTool Configuration")
            print("Configuration options will be available in future updates.")
            input("Press Enter to continue...")
        elif choice == "8":
            install_tools()
        elif choice == "9":
            show_help()
        else:
            print("Invalid option. Please select 0-9.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
