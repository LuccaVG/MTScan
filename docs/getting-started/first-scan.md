# Your First Scan

This tutorial explains the complete MTScan chain. Use an isolated lab asset that you own or are authorized to test.

## Before scanning

Record the authorized target, allowed ports, time window, expected traffic level, and whether vulnerability templates are allowed. Start with a dry run.

```bash
python src/workflow.py --all -host <authorized-target> --dry-run
```

## Run the chain

```bash
python src/workflow.py \
  --all \
  -host <authorized-target> \
  --json-output
```

`--all` enables saved reporting automatically. Structured scanner output is used when supported so MTScan can parse richer Nuclei metadata.

## What happens

1. Naabu discovers TCP services.
2. HTTPX probes the discovered endpoints for HTTP(S).
3. Nuclei receives the HTTP(S) URLs confirmed by HTTPX.
4. MTScan parses Nuclei findings, extracts severity/CVE/CWE metadata, and writes `vulnerability_report.md`.
5. Intermediate conventional scanner files are cleaned after report generation; explicit Nuclei exports are separate.

If Naabu finds no parsable ports, HTTPX probes the original target. If HTTPX confirms no HTTP(S) URLs in a live chain, Nuclei is skipped rather than scanning unrelated TCP services.

## Read the report

Start with:

- **Overall risk** and **Executive Summary**.
- **Priority Findings** for critical/high/medium/low Nuclei results.
- **CVE Summary** for identifiers parsed from Nuclei metadata or output.
- **Exposure Context** for open ports and HTTP services.
- **Commands** for redacted execution previews.

A CVE identifier in a report means Nuclei associated a finding with that identifier. It is not proof that exploitation succeeded. Confirm the affected product/version and vendor advisory.

## Re-scan after remediation

Run the same profile and target after applying a fix. Compare findings, exposed services, and CVE references rather than treating one successful scan as permanent assurance.
