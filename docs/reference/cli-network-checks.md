# CLI connectivity checks

MTScan 1.0.2 makes the CLI public-connectivity preflight target-aware.

For ordinary scans, MTScan skips the public Internet check when the validated target is explicitly non-public, including loopback addresses, private and link-local IP ranges, private/link-local CIDRs, IPv6 unique-local ranges, and `localhost`.

Examples that do not require public Internet connectivity:

```bash
python src/workflow.py --httpx -host http://127.0.0.1:18080
python src/workflow.py --naabu -host 10.10.10.10
python src/workflow.py --naabu -host 192.168.50.0/24
```

Public targets still use the connectivity preflight. `--skip-network-check` remains an explicit override for cases where the operator intentionally wants to proceed without that check.

Operations that themselves require public connectivity are exceptions. In particular, `--update-templates` still performs the connectivity check even when the scan target is private.
