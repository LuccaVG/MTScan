# Quickstart

This tutorial validates MTScan without requiring an external target.

## 1. Check the scanners

```bash
python src/workflow.py --check-tools
```

For live scans, all required scanners for the selected mode must be available unless `--force-tools` is explicitly used.

## 2. Preview a complete chain

Dry-run mode validates the request and prints redacted scanner commands without executing the tools:

```bash
python src/workflow.py --all -host https://example.com --dry-run
```

## 3. Start a local HTTP fixture

In a separate terminal:

```bash
python -m http.server 18080 --bind 127.0.0.1
```

This is a plain local web server, not a deliberately vulnerable target.

## 4. Run HTTPX through MTScan

```bash
python src/workflow.py \
  --httpx \
  -host http://127.0.0.1:18080 \
  --title \
  --status-code \
  --web-server \
  --save-output
```

MTScan 1.0.2 recognizes loopback and other explicitly non-public targets and does not require a public Internet connectivity preflight for ordinary scans. `--skip-network-check` remains available as a manual override for other environments. Operations that explicitly need public connectivity, such as `--update-templates`, still perform the connectivity check.

MTScan should report the local service as reachable and generate `vulnerability_report.md` in a timestamped result directory.

## 5. Open the web interface

```bash
python src/app_server.py --host 127.0.0.1 --port 8765
```

On first startup, copy the one-time password printed in the server terminal and sign in as `admin`. Change the password when prompted.

## 6. Stop the fixture

Return to the `http.server` terminal and press `Ctrl+C`.

## Next step

See [Your first scan](first-scan.md) for the chained workflow and authorization checklist.
