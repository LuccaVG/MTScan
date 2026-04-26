# MTScan

MTScan is a Linux-focused command-line toolkit that runs three ProjectDiscovery
tools:

- `naabu` for port discovery
- `httpx` for HTTP service analysis
- `nuclei` for vulnerability scanning

The project has two supported interfaces:

- Interactive menu: `python3 mtscan.py`
- Direct CLI: `python3 src/workflow.py`

There is no app/UI layer yet.

## Requirements

- Native Linux VM or host
- Python 3.8+
- Internet access for installation, template updates, and public target scans
- `naabu`, `httpx`, and `nuclei`
- Go, if installing the tools from source

## Install

Run the Linux installer from the project root:

```bash
sudo python3 install/setup.py
```

The installer exposes Go-installed tools through `/usr/local/bin` when run with
`sudo`. If your shell cannot find them, make sure `/usr/local/bin` is in `PATH`:

```bash
export PATH="$PATH:/usr/local/bin"
```

## Usage

Interactive menu:

```bash
python3 mtscan.py
```

Run one tool:

```bash
python3 src/workflow.py -naabu -host example.com --top-ports 100
python3 src/workflow.py -httpx -host example.com --title --status-code --tech-detect
python3 src/workflow.py -nuclei -host https://example.com --severity critical,high
```

Check the Linux scanner environment:

```bash
python3 src/workflow.py --check-tools
```

Run the full chain:

```bash
python3 src/workflow.py --all -host example.com --top-ports 100 --save-output
```

In the interactive menu, option `[4]` now offers default, fast, stealth, deep,
and custom per-tool chain configuration before launching the scan.

The full chain runs:

1. `naabu` against the target.
2. `httpx` against discovered hosts/ports, or the original target if no ports are saved.
3. `nuclei` against discovered HTTP URLs, or `http://target` and `https://target` as fallback.

## Outputs

When `--save-output` or `--all` is used, MTScan creates a `results_*` directory
with tool output files, `comprehensive_scan_report.txt`, and
`security_findings_report.md`.

`security_findings_report.md` is generated from saved nuclei output. Use
`--json-output` when you want richer finding details, references, and
remediation text in that report.

Useful output flags:

- `--json-output` for JSON/JSONL where supported
- `-o ./results` to choose an output directory
- `--tool-silent` to ask tools for quieter output

## Troubleshooting

If tools are not found:

```bash
which naabu
which httpx
which nuclei
echo "$PATH"
export PATH="$PATH:$HOME/go/bin"
```

If nuclei templates are stale:

```bash
python3 src/workflow.py -nuclei -host https://example.com --update-templates
```

If scanner binaries are outdated, use menu option `[8]` and choose
`Update scanner binaries to latest`. The full installer also installs ProjectDiscovery
tools from `@latest`. Go builds use a disk-backed cache under
`$GOPATH/mtscan-build` to avoid Kali `/tmp` space issues during nuclei builds.
Installer retries are timeout-bound and stop the full child process tree before
moving to the next attempt.

Quick Linux smoke test without launching scanners:

```bash
python3 src/workflow.py --dry-run --all -host example.com --top-ports 100 --save-output --json-output
```

If the VM network check fails but you know connectivity is available:

```bash
python3 src/workflow.py --skip-network-check -httpx -host example.com
```

Use only targets you own or are explicitly authorized to test.
