# Scan Workflow

## Chained mode

A live `--all` scan is sequential:

```text
validated target
    |
    v
Naabu
    | open host:port endpoints
    v
HTTPX
    | confirmed http:// or https:// URLs
    v
Nuclei
    | findings
    v
normalize -> classify -> report -> history summary
```

## Stage 1: target validation

MTScan rejects empty targets, control characters, whitespace, unsupported URL schemes, malformed CIDR prefixes, invalid port values, invalid severity values, and out-of-range numeric options before scanner execution.

HTTP(S) URLs are accepted as URL targets. Bare inputs can be IP addresses, CIDRs, hostnames, IPv6 forms, or host:port-like values that pass the target grammar.

## Stage 2: Naabu

Naabu performs TCP discovery. MTScan parses discovered `host:port` endpoints from text or structured output.

If Naabu fails, HTTPX and Nuclei are not treated as successful downstream scans.

If Naabu completes but MTScan parses no open endpoints, HTTPX probes the original target rather than inventing TCP services.

## Stage 3: HTTPX

When Naabu produced endpoints, MTScan writes a temporary HTTPX target list and probes those endpoints. HTTPX output is parsed for actual `http://` and `https://` URLs.

## Stage 4: Nuclei

In a live chain, Nuclei receives the URLs confirmed by HTTPX. If HTTPX confirms no HTTP(S) targets, MTScan skips Nuclei successfully with an explanatory message rather than sending Nuclei to SSH, FTP, SMTP, or other non-HTTP TCP services.

This decision is recorded in [ADR-0004](../adr/0004-httpx-confirmed-urls-to-nuclei.md).

## Stage 5: finding normalization

MTScan parses Nuclei text or JSONL findings and normalizes:

- Name and template ID.
- Severity.
- Matched target.
- CVE/CWE identifiers.
- Description, impact, remediation, references, tags, and extracted results when available.
- A high-level category such as Known Vulnerability, RCE, SQL Injection, XSS, SSRF, auth risk, exposure, TLS, or misconfiguration.

Critical/high/medium/low findings are counted as security findings. Info/unknown matches are observations.

## Stage 6: reporting and cleanup

MTScan writes `vulnerability_report.md`, hydrates result information needed by the summary, and cleans conventional scanner/handoff intermediates. Normalized scan summaries can then be persisted to Cassandra or the file fallback.
