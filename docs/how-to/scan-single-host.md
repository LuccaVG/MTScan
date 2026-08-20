# Scan a Single Host

## Goal

Run one scanner or the complete MTScan chain against an authorized hostname, IP address, host:port, or HTTP(S) URL.

## Complete chain

```bash
python src/workflow.py --all -host target.example --json-output
```

## Port discovery only

```bash
python src/workflow.py --naabu -host target.example --top-ports 1000 --save-output
```

## HTTP service detection only

```bash
python src/workflow.py \
  --httpx \
  -host https://target.example \
  --title \
  --status-code \
  --tech-detect \
  --web-server \
  --save-output
```

## Nuclei only

```bash
python src/workflow.py \
  --nuclei \
  -host https://target.example \
  --severity critical,high,medium \
  --json-output \
  --save-output
```

## Use a port-specific URL

```bash
python src/workflow.py --httpx -host https://target.example:8443 --status-code --save-output
```

## Notes

- URL targets accept only `http://` and `https://` schemes.
- Whitespace and control characters are rejected in targets.
- `--save-output` creates the report for individual-tool scans; `--all` already enables report output.
- Use `--dry-run` before a production change window.
