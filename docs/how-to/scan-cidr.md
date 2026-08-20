# Scan a CIDR Range

## Goal

Discover services across an authorized IPv4 or IPv6 network and optionally continue through the HTTPX and Nuclei chain.

## Dry run first

```bash
python src/workflow.py --all -host <authorized-cidr> --dry-run
```

## Naabu discovery

```bash
python src/workflow.py \
  --naabu \
  -host <authorized-cidr> \
  --top-ports 100 \
  --rate 100 \
  --save-output
```

## Complete chain

```bash
python src/workflow.py \
  --all \
  -host <authorized-cidr> \
  --top-ports 100 \
  --rate 100 \
  --json-output
```

## Scope and availability notes

CIDR scans can generate substantially more traffic than a single-host scan. Confirm the network range, route boundaries, maintenance window, rate limit, and ownership before starting.

Use `--stealth` for a conservative preset, but do not assume that a lower rate makes an unauthorized scan acceptable.

MTScan validates numeric CIDR prefix lengths. It does not determine whether the network is legally or contractually in scope.
