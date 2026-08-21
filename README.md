# MTScan

![Version](https://img.shields.io/badge/version-1.0.2-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT%20OR%20BSD--3--Clause-green)

MTScan is a Linux-focused vulnerability analysis toolkit that orchestrates ProjectDiscovery `naabu`, `httpx`, and `nuclei` through a shared CLI and authenticated local web interface.

**Current version:** 1.0.2.

> Use MTScan only on systems you own or are explicitly authorized to test.

## Features

- Chained `naabu -> httpx -> nuclei` vulnerability workflow.
- Individual Naabu, HTTPX, and Nuclei execution.
- CVE/CWE extraction from Nuclei findings and remediation-focused Markdown reports.
- Authenticated local web dashboard with scan history, schedules, findings, assets, and health status.
- Cassandra-backed history with a local JSONL fallback.
- Target and option validation, command redaction, local-first web binding, and defensive HTTP headers.
- Compatibility handling for current ProjectDiscovery HTTPX and Nuclei CLI flags.
- Automated unit, runtime-integration, and security validation in GitHub Actions.

## Requirements

- Native Linux host or VM.
- Python 3.8 or newer.
- `naabu`, `httpx`, and `nuclei` for live scans.
- Internet access when installing dependencies or updating Nuclei templates.

The installer supports Debian, Ubuntu, Kali Linux, and Arch Linux. See [Installation](docs/getting-started/installation.md) for platform-specific notes.

## Installation

```bash
sudo python install/setup.py
```

Review the installer before running it as root. It installs system packages, ProjectDiscovery tools, Python dependencies, and—on supported APT-based systems—a local Cassandra service.

## Quick start

Check scanner availability:

```bash
python src/workflow.py --check-tools
```

Preview a complete scan without sending traffic:

```bash
python src/workflow.py --all -host https://example.com --dry-run
```

Start the local web interface:

```bash
python src/app_server.py --host 127.0.0.1 --port 8765
```

On first startup, MTScan prints a randomly generated one-time password for the `admin` account to the local server console. The password must be changed after the first login.

Start the interactive launcher:

```bash
python mtscan.py
```

## Basic usage

Run HTTPX against an authorized web service:

```bash
python src/workflow.py --httpx -host https://target.example --title --status-code --web-server --save-output
```

Run the complete chain:

```bash
python src/workflow.py --all -host target.example --json-output
```

Filter Nuclei findings:

```bash
python src/workflow.py --nuclei -host https://target.example --severity critical,high --json-output --save-output
```

## Architecture overview

```text
Target
  |
  v
Naabu          TCP discovery
  |
  v
HTTPX          confirms HTTP(S) services
  |
  v
Nuclei         templates / CVE and exposure detection
  |
  v
MTScan report  vulnerability_report.md
```

The CLI and web app share `src/tool_runner.py`, which owns validation, command construction, scanner execution, result parsing, chained target propagation, redaction, and report generation. Runtime compatibility guards keep MTScan aligned with supported ProjectDiscovery CLI behavior while preserving the existing public MTScan interface.

## Documentation

The full documentation is organized with the [Diátaxis framework](docs/README.md):

- [Getting started](docs/getting-started/quickstart.md)
- [How-to guides](docs/how-to/scan-single-host.md)
- [Reference](docs/reference/cli.md)
- [Concepts and design](docs/concepts/architecture.md)
- [Development](docs/development/architecture.md)
- [CI](docs/development/ci.md)
- [Runtime validation](docs/development/runtime-validation.md)
- [Architecture Decision Records](docs/adr/0001-use-projectdiscovery-tools.md)

## Security and authorization

MTScan performs active security scanning. Define scope before scanning, use conservative rates when availability matters, and do not scan third-party systems without explicit authorization. See [SECURITY.md](SECURITY.md) and the [security model](docs/concepts/security-model.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [docs/development/coding-standards.md](docs/development/coding-standards.md).

## License

MTScan original project files are available under `Apache-2.0 OR MIT OR BSD-3-Clause`. Third-party tools retain their upstream licenses. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [licensing reference](docs/reference/licensing.md).
