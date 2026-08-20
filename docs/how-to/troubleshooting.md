# Troubleshooting

## Scanner reported as missing

Run:

```bash
python3 src/workflow.py --check-tools
```

Then verify PATH:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

MTScan recognizes both `httpx-toolkit` and `httpx` for the ProjectDiscovery HTTPX scanner and verifies candidates with version/help probes.

## `httpx` is the wrong program

Some Linux distributions package an unrelated program named `httpx`. MTScan probes the executable and prefers a candidate that behaves like ProjectDiscovery HTTPX. Install ProjectDiscovery HTTPX and ensure it is reachable in `/usr/local/bin` or `$HOME/go/bin`.

## Network connectivity check fails

Use `--skip-network-check` only when you understand why the check is failing, such as an isolated lab with no Internet route:

```bash
python3 src/workflow.py --httpx -host http://127.0.0.1:18080 --skip-network-check
```

The flag skips MTScan's preflight check; it does not make an unreachable scanner target reachable.

## Web app will not bind remotely

This is intentional. The default security boundary is loopback.

```bash
python3 src/app_server.py --host 0.0.0.0 --port 8765 --allow-remote
```

Only do this on a trusted lab network or behind a separately secured reverse proxy.

## I do not know the first-run password

On first initialization, MTScan prints a random one-time password in the local server console. It is not `admin`. If authentication data already exists, MTScan does not generate a new first-run credential each restart.

The local fallback auth file is normally `data/auth.json`; Cassandra stores the app auth record in its settings table. Do not delete authentication storage casually on a system with scan history you need to preserve.

## Cassandra is unavailable

By default, `MTSCAN_STORAGE_BACKEND=auto` tries Cassandra and falls back to local JSONL storage. Check:

```bash
sudo systemctl status cassandra
```

Or explicitly select file storage:

```bash
export MTSCAN_STORAGE_BACKEND=file
python3 src/app_server.py
```

## Nuclei finds no CVEs

A CVE appears only when Nuclei produces a matching finding whose template metadata or output contains a CVE identifier. Check that:

- Nuclei templates are current.
- The relevant template is enabled by severity/tag/template filters.
- HTTPX confirmed the expected HTTP(S) service in chained mode.
- The target actually matches the template conditions.

No CVE result is not proof that the target has no vulnerabilities.

## Report contains fewer details than expected

Use `--json-output` so Nuclei can provide structured classification, description, reference, and remediation metadata when the template includes it.

## Scan exits with code 2

The target or one of the validated options is invalid. See [Exit codes](../reference/exit-codes.md) and [CLI reference](../reference/cli.md).
