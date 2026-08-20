# Installation

## Goal

Install MTScan and its scanner dependencies on a supported native Linux host or VM.

## Supported environments

The installer recognizes Debian, Ubuntu, Kali Linux, and Arch Linux. Live scanner execution is Linux-only. Cassandra automatic installation is currently aimed at APT-based distributions.

## Requirements

- Python 3.8+.
- Root or sudo access for the full installer.
- Internet access for packages, Go modules, scanner installation, and template updates.
- At least a few gigabytes of free disk space for system packages, Go build caches, scanners, and Nuclei templates.

## Install

Clone the repository and run from the project root:

```bash
sudo python install/setup.py
```

The installer can:

1. Validate Linux, distribution, Python, privileges, disk space, and connectivity.
2. Install system packages and build dependencies.
3. Install Python runtime dependencies from `config/requirements.txt`.
4. Install/configure a native Cassandra service on supported APT systems.
5. Configure Go and install/update Naabu, HTTPX, and Nuclei.
6. Generate local configuration files and verify the runtime.

## Privileged-operation warning

`install/setup.py` performs system-level changes and may install packages, configure services, create files under `/etc` and `/usr/local`, and attempt package-manager recovery. Review the installer before running it with root privileges, especially on a workstation or production host.

## Verify

```bash
python src/workflow.py --check-tools
```

Expected result: Naabu, HTTPX, and Nuclei are reported as available.

You can also verify Python syntax and tests:

```bash
python -m py_compile mtscan.py src/workflow.py src/tool_runner.py src/app_server.py src/scan_storage.py
python -m unittest discover -s tests -v
```

## PATH troubleshooting

The installer attempts to expose scanner binaries through `/usr/local/bin`. If needed:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

On Kali, ProjectDiscovery HTTPX may be exposed as `httpx-toolkit`; MTScan checks both `httpx-toolkit` and `httpx` and verifies that the candidate responds like the ProjectDiscovery scanner.

## Cassandra

MTScan can operate with a local JSONL history backend if Cassandra is unavailable. To start Cassandra manually on a systemd host:

```bash
sudo systemctl enable --now cassandra
```

See [Configuration](../reference/configuration.md) for storage environment variables.

## Next step

Continue with [Quickstart](quickstart.md).
