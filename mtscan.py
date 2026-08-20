#!/usr/bin/env python3
"""MTScan interactive launcher.

The browser application is the primary interface. This launcher keeps local
management tasks available without duplicating the scanner workflow implemented
in ``src.tool_runner`` and ``src.workflow``.
"""

from __future__ import annotations

import datetime
import http.client
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.browser_opener import open_url
from src.tool_runner import get_executable_path

BANNER = """╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║          ███╗   ███╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗          ║
║          ████╗ ████║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║          ║
║          ██╔████╔██║   ██║   ███████╗██║     ███████║██╔██╗ ██║          ║
║          ██║╚██╔╝██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║          ║
║          ██║ ╚═╝ ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║          ║
║          ╚═╝     ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝          ║
║                                                                          ║
║                   Multi Tool Scan - Interactive Menu                     ║
║                  Linux Vulnerability Analysis Toolkit                    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝"""

PROJECTDISCOVERY_GO_MODULES = {
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


def clear_screen() -> None:
    """Clear the terminal without invoking a shell."""
    print("\033[2J\033[H", end="")


def print_banner() -> None:
    print(BANNER)
    print()


def find_tool_path(tool: str) -> Optional[str]:
    return get_executable_path(tool)


def check_tools_status() -> Dict[str, Dict[str, Optional[str]]]:
    status: Dict[str, Dict[str, Optional[str]]] = {}
    for tool in ("naabu", "httpx", "nuclei"):
        path = find_tool_path(tool)
        status[tool] = {"installed": "yes" if path else "no", "path": path}
    return status


def print_tools_status() -> None:
    print("TOOL STATUS CHECK:")
    print("=" * 60)
    missing = []
    for tool, info in check_tools_status().items():
        if info["path"]:
            print(f"  [OK]      {tool.upper():<8} Available at {info['path']}")
        else:
            print(f"  [MISSING] {tool.upper():<8} Not found")
            missing.append(tool)
    if missing:
        print(f"\n[WARNING] Missing tools: {', '.join(missing)}")
        print("[ACTION]  Use option [5] to install/update tools.")
    else:
        print("\n[STATUS] All scanner tools are installed and ready.")
    print()


def print_main_menu() -> None:
    print("WEB APPLICATION:")
    print("=" * 60)
    print("  [1] Launch Local Web App")
    print("      Open the authenticated monitoring console on localhost")
    print()
    print("MANAGEMENT OPERATIONS:")
    print("=" * 60)
    print("  [2] View Previous Results")
    print("  [3] Update Nuclei Templates")
    print("  [4] Tool Configuration")
    print("  [5] Install/Update Tools")
    print("  [6] Help & Documentation")
    print("  [0] Exit Program")
    print("=" * 60)


def result_directories() -> list[Path]:
    return sorted(
        (path for path in PROJECT_ROOT.glob("results_*") if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def view_result_details(result_dir: Path) -> None:
    clear_screen()
    print_banner()
    print(f"SCAN RESULTS: {result_dir.name}")
    print("=" * 60)

    report = result_dir / "vulnerability_report.md"
    if report.is_file():
        try:
            print(report.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            print(f"Could not read report: {exc}")
    else:
        print("No vulnerability_report.md found.")
        print("\nDirectory contents:")
        try:
            for path in sorted(result_dir.iterdir(), key=lambda item: item.name):
                if path.is_file():
                    print(f"  {path.name} ({path.stat().st_size} bytes)")
                elif path.is_dir():
                    print(f"  {path.name}/")
        except OSError as exc:
            print(f"Could not list result directory: {exc}")

    input("\nPress Enter to continue...")


def view_results() -> None:
    clear_screen()
    print_banner()
    print("PREVIOUS SCAN RESULTS:")
    print("=" * 60)

    directories = result_directories()[:10]
    if not directories:
        print("No previous scan results found.")
        input("\nPress Enter to continue...")
        return

    for index, path in enumerate(directories, 1):
        timestamp = datetime.datetime.fromtimestamp(path.stat().st_mtime)
        print(f"  [{index}] {path.name} - {timestamp:%Y-%m-%d %H:%M:%S}")
    print("  [0] Back")

    while True:
        choice = input(f"\nSelect result [0-{len(directories)}]: ").strip()
        if choice == "0":
            return
        try:
            index = int(choice) - 1
        except ValueError:
            print("Please enter a number.")
            continue
        if 0 <= index < len(directories):
            view_result_details(directories[index])
            return
        print("Invalid selection.")


def update_templates() -> None:
    clear_screen()
    print_banner()
    nuclei = find_tool_path("nuclei")
    if not nuclei:
        print("nuclei was not found. Use option [5] first.")
        input("\nPress Enter to continue...")
        return

    print("UPDATING NUCLEI TEMPLATES:")
    print("=" * 60)
    try:
        result = subprocess.run([nuclei, "-update-templates"], timeout=300, check=False)
        if result.returncode == 0:
            print("Templates updated successfully.")
        else:
            print(f"Template update exited with code {result.returncode}.")
    except subprocess.TimeoutExpired:
        print("Template update timed out after 5 minutes.")
    except OSError as exc:
        print(f"Template update failed: {exc}")
    input("\nPress Enter to continue...")


def expose_updated_tool(tool: str, source_path: Path) -> bool:
    target_name = "httpx-toolkit" if tool == "httpx" else tool
    target_path = Path("/usr/local/bin") / target_name

    try:
        if target_path.exists() or target_path.is_symlink():
            target_path.unlink()
        target_path.symlink_to(source_path)
        print(f"[OK] {tool} exposed at {target_path}")
        return True
    except (OSError, PermissionError):
        pass

    try:
        result = subprocess.run(
            ["sudo", "ln", "-sfn", str(source_path), str(target_path)],
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[WARN] Could not expose {tool}: {exc}")
        return False

    if result.returncode == 0:
        print(f"[OK] {tool} exposed at {target_path}")
        return True
    print(f"[WARN] Could not expose {tool} at {target_path}")
    return False


def go_path() -> Optional[Path]:
    try:
        result = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return Path(value) if result.returncode == 0 and value else None


def update_scanner_tools() -> bool:
    if shutil.which("go") is None:
        print("[ERROR] Go is required to update scanner tools.")
        return False

    env = os.environ.copy()
    success_count = 0
    for tool, module in PROJECTDISCOVERY_GO_MODULES.items():
        print(f"\n[UPDATE] {tool}")
        try:
            result = subprocess.run(
                ["go", "install", "-trimpath", module],
                env=env,
                timeout=900,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print(f"[ERROR] {tool} update timed out.")
            continue
        except OSError as exc:
            print(f"[ERROR] {tool} update failed: {exc}")
            continue

        if result.returncode != 0:
            print(f"[ERROR] {tool} update exited with code {result.returncode}.")
            continue

        gopath = go_path()
        binary = gopath / "bin" / tool if gopath else None
        if binary and binary.is_file():
            expose_updated_tool(tool, binary)
        success_count += 1

    print(f"\n[SUMMARY] Updated {success_count}/3 scanner binaries.")
    return success_count == 3


def install_tools() -> None:
    clear_screen()
    print_banner()
    print("INSTALLING/UPDATING TOOLS:")
    print("=" * 60)
    print("  [1] Update ProjectDiscovery scanner binaries")
    print("  [2] Run full setup installer")
    choice = input("Select option [1-2]: ").strip() or "1"

    if choice == "1":
        update_scanner_tools()
    elif choice == "2":
        setup = PROJECT_ROOT / "install" / "setup.py"
        if not setup.is_file():
            print("install/setup.py was not found.")
        else:
            command = [sys.executable, str(setup)]
            try:
                result = subprocess.run(command, cwd=PROJECT_ROOT, timeout=1800, check=False)
                if result.returncode != 0:
                    print("Setup needs elevated privileges or reported an error; retrying with sudo.")
                    subprocess.run(
                        ["sudo", sys.executable, str(setup)],
                        cwd=PROJECT_ROOT,
                        timeout=1800,
                        check=False,
                    )
            except subprocess.TimeoutExpired:
                print("Installation timed out after 30 minutes.")
            except OSError as exc:
                print(f"Installation failed: {exc}")
    else:
        print("Invalid option.")

    input("\nPress Enter to continue...")


def storage_backend_setting() -> str:
    return os.environ.get("MTSCAN_STORAGE_BACKEND", "auto").strip().lower()


def cassandra_driver_available() -> bool:
    try:
        import cassandra.cluster  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


def tcp_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def prepare_cassandra_for_web_app() -> None:
    backend = storage_backend_setting()
    if backend in {"file", "off", "none", "disabled"}:
        print(f"[DB] Cassandra skipped because MTSCAN_STORAGE_BACKEND={backend}.")
        return
    if not cassandra_driver_available():
        print("[DB] cassandra-driver is unavailable; JSONL history will be used.")
        return

    host = "127.0.0.1"
    try:
        port = int(os.environ.get("MTSCAN_CASSANDRA_PORT", "9042"))
    except ValueError:
        port = 9042
    if tcp_port_open(host, port):
        print(f"[DB] Cassandra is reachable at {host}:{port}.")
    else:
        print("[DB] Cassandra is not reachable; JSONL history will be used.")


def wait_for_web_app(url: str, process: subprocess.Popen, timeout: float = 10.0) -> bool:
    """Check only the local HTTP endpoint used by the launcher."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        print("[APP] Refusing readiness check for a non-loopback URL.")
        return False

    port = parsed.port or 80
    deadline = time.monotonic() + timeout
    last_error: Optional[Exception] = None

    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            print(f"[APP] Web app exited before it became ready (code {return_code}).")
            return False

        connection: Optional[http.client.HTTPConnection] = None
        try:
            connection = http.client.HTTPConnection(parsed.hostname, port, timeout=1)
            connection.request("GET", "/api/health")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return True
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
            time.sleep(0.25)
        finally:
            if connection is not None:
                connection.close()

    if last_error:
        print(f"[APP] Readiness check failed: {last_error}")
    return False


def launch_web_app() -> None:
    clear_screen()
    print_banner()
    print("LOCAL WEB APP:")
    print("=" * 60)

    port_text = input("Port [8765]: ").strip() or "8765"
    try:
        port = int(port_text)
    except ValueError:
        print("Invalid port.")
        input("Press Enter to continue...")
        return
    if not 1 <= port <= 65535:
        print("Port must be between 1 and 65535.")
        input("Press Enter to continue...")
        return

    host = "127.0.0.1"
    app = PROJECT_ROOT / "src" / "app_server.py"
    if not app.is_file():
        print("src/app_server.py was not found.")
        input("Press Enter to continue...")
        return

    print_tools_status()
    prepare_cassandra_for_web_app()

    url = f"http://{host}:{port}"
    command = [
        sys.executable,
        "-u",
        str(app),
        "--host",
        host,
        "--port",
        str(port),
        "--skip-tool-check",
        "--no-browser",
    ]
    env = os.environ.copy()
    env.setdefault("MTSCAN_STORAGE_BACKEND", "auto")

    process: Optional[subprocess.Popen] = None
    try:
        process = subprocess.Popen(command, cwd=PROJECT_ROOT, env=env)
        if wait_for_web_app(url, process):
            print(f"[APP] Ready at {url}")
            if not open_url(url):
                print(f"[APP] Open this URL in your browser: {url}")
        else:
            print(f"[APP] Server did not become ready. Check {url} manually if it is still running.")
        return_code = process.wait()
        if return_code != 0:
            print(f"[APP] Web app exited with code {return_code}.")
    except KeyboardInterrupt:
        print("\n[APP] Stopping web app...")
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    except OSError as exc:
        print(f"[APP] Could not start web app: {exc}")

    input("\nPress Enter to return to main menu...")


def show_help() -> None:
    clear_screen()
    print_banner()
    print("HELP & DOCUMENTATION:")
    print("=" * 60)
    print("  Web app:      python3 src/app_server.py --host 127.0.0.1 --port 8765")
    print("  CLI workflow: python3 src/workflow.py --help")
    print("  Usage guide:  docs/USAGE.md")
    print("  Install guide: docs/INSTALL.md")
    print("  Security:     SECURITY.md")
    input("\nPress Enter to continue...")


def ensure_linux() -> bool:
    if platform.system().lower() == "linux":
        return True
    print("MTScan scanner execution is supported on native Linux systems only.")
    return False


def main() -> None:
    if not ensure_linux():
        raise SystemExit(1)

    while True:
        clear_screen()
        print_banner()
        print_tools_status()
        print_main_menu()
        choice = input("Select option [0-6]: ").strip()

        if choice == "0":
            return
        if choice == "1":
            launch_web_app()
        elif choice == "2":
            view_results()
        elif choice == "3":
            update_templates()
        elif choice == "4":
            print("\nScanner configuration is managed from the web application.")
            input("Press Enter to continue...")
        elif choice == "5":
            install_tools()
        elif choice == "6":
            show_help()
        else:
            print("Invalid option. Please select 0-6.")
            input("Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye.")
        raise SystemExit(130)
