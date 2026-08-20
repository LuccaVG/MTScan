# Use Structured JSON Mode

## Goal

Make MTScan request structured scanner output so vulnerability reports can include richer Nuclei metadata.

## Enable structured mode

```bash
python3 src/workflow.py \
  --all \
  -host target.example \
  --json-output
```

For a Nuclei-only scan:

```bash
python3 src/workflow.py \
  --nuclei \
  -host https://target.example \
  --json-output \
  --save-output
```

## Important: this is not a durable JSON report export

In `1.0.0-alpha`, `--json-output` selects JSON/JSONL scanner output **for parsing**. MTScan's saved-scan model is report-oriented: conventional scanner intermediate files are consumed by `vulnerability_report.md` and cleaned during summary generation.

Therefore, do not treat `--json-output` as a guarantee that `naabu_results.json`, `httpx_results.json`, or `nuclei_results.jsonl` will remain after the scan.

## Durable machine-readable export

For Nuclei findings, use an explicit upstream export that MTScan does not treat as a conventional intermediate, for example SARIF:

```bash
python3 src/workflow.py \
  --nuclei \
  -host https://target.example \
  --json-output \
  --sarif-export ./exports/nuclei.sarif \
  --save-output
```

A dedicated MTScan JSON report format is not yet a stable `1.0.0-alpha` interface. See [Limitations](../concepts/limitations.md) and [ADR-0003](../adr/0003-report-only-output.md).
