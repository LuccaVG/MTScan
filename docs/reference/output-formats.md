# Output Formats

## Canonical MTScan report

A saved scan generates:

```text
vulnerability_report.md
```

The report contains the target, overall risk, severity counts, finding categories, CVE summary, exposure context, priority findings, remediation guidance, tool execution status, and redacted command previews.

## Conventional scanner intermediates

During report generation MTScan may create:

| Tool | Text | Structured | CSV |
|---|---|---|---|
| Naabu | `naabu_results.txt` | `naabu_results.json` | `naabu_results.csv` |
| HTTPX | `httpx_results.txt` | `httpx_results.json` | `httpx_results.csv` |
| Nuclei | `nuclei_results.txt` | `nuclei_results.jsonl` | `nuclei_results.csv` |

Chained scans also use `httpx_targets.txt` and `nuclei_targets.txt` for stage handoff.

## Retention model

MTScan `1.0.0-alpha` uses a report-oriented saved-output model. Conventional scanner intermediates and chain handoff files are consumed by report generation and then cleaned up by the summary path. The in-memory result object is hydrated before cleanup so the web/CLI summary can still be produced.

Do not rely on conventional intermediate filenames as durable evidence artifacts.

## Explicit upstream exports

Nuclei options such as the following create explicit exports outside the conventional intermediate model:

```bash
--markdown-export <directory>
--sarif-export <file>
--store-resp
--store-resp-dir <directory>
```

These can contain sensitive target data and should be protected accordingly.

## Structured parsing mode

`--json-output` requests structured output where supported. Nuclei uses JSONL, which gives MTScan richer access to:

- Template ID and name.
- Severity.
- Matched target.
- Description and remediation metadata.
- Tags and references.
- CVE/CWE classification fields.

Structured mode improves report parsing; it is not a dedicated MTScan JSON report format.

## History storage

The web app and saved CLI scans persist normalized summaries to Cassandra or the local JSONL fallback. History records are not equivalent to raw scanner evidence and intentionally omit/transform some local path and command details.
