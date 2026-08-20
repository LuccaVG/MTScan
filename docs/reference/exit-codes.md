# Exit Codes

This page documents the primary CLI `src/workflow.py`.

| Code | Meaning |
|---:|---|
| `0` | Requested operation completed successfully |
| `1` | Usage/preflight failure, missing tool, scanner failure, failed chain stage, or other non-validation failure |
| `2` | MTScan target or option validation failed (`ScanInputError`) |
| `130` | Interrupted by `Ctrl+C` / SIGINT |

## Scanner return codes

Individual scanner return codes are captured in MTScan result metadata. The top-level MTScan CLI generally returns `1` when one or more selected tools fail rather than promising to forward every upstream code unchanged.

## `--check-tools`

```bash
python src/workflow.py --check-tools
```

Returns `0` when required scanner probes succeed and `1` when the tool check fails.

## Invalid request example

```bash
python src/workflow.py --httpx -host ftp://target.example
```

Only HTTP(S) URL schemes are accepted for URL targets, so the request exits with code `2`.
