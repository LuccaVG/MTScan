# ADR-0003: Report-Oriented Saved Output

**Status:** Accepted  
**Date:** 2026-08-20

## Context

Naabu, HTTPX, and Nuclei can each generate text, JSON/JSONL, CSV, and other artifacts. Keeping every intermediate by default creates duplicate data, exposes more sensitive target details, and makes the result directory harder to understand.

## Decision

The canonical MTScan saved artifact is `vulnerability_report.md`.

Conventional scanner result files and chained handoff lists are intermediate inputs to report generation. MTScan hydrates the required result data, writes the report, and cleans those conventional intermediates during the summary path.

Explicit upstream exports such as Nuclei SARIF, Markdown export, or stored responses are separate operator-requested artifacts and are not treated as the canonical MTScan report.

## Consequences

### Positive

- One obvious human-readable artifact per saved scan.
- Less duplicate sensitive data retained by default.
- Report contains normalized severity, CVE/CWE, exposure, commands, and remediation context.

### Negative

- Conventional raw scanner files are not durable evidence by default.
- Structured `--json-output` is primarily a parsing mode, not a retained MTScan JSON report.
- Engagements requiring raw evidence must request explicit exports and protect them separately.

## Alternatives considered

- Keep all raw scanner outputs after every scan.
- Make JSON the only canonical report.

The first increases sensitive-data retention and clutter; the second is less convenient for direct human review and is not yet a stable alpha schema.
