# Maintainer Guide

This guide is for people changing MTScan, not just running it. It explains the
shape of the project, the safety expectations behind the code, and the checks
that should pass before a change is trusted.

MTScan has a small surface area on purpose: a shared Python runner, a CLI
workflow, an interactive menu, and a local web app. When behavior changes, keep
those entry points aligned.

## Project Shape

Core paths:

- `src/tool_runner.py`: command construction, target validation, process
  execution, scanner output parsing, summaries, and report generation.
- `src/workflow.py`: direct CLI entry point. It translates CLI flags into
  `tool_runner` calls.
- `mtscan.py`: interactive terminal menu. It delegates scan execution to
  `src/workflow.py`.
- `src/app_server.py`: standard-library local web server and JSON API.
- `src/scan_storage.py`: completed scan summary storage for the web app.
- `web/`: static dashboard assets.
- `tests/`: regression tests for the runner, storage, and web server helpers.

The important rule: scanner behavior belongs in `src/tool_runner.py`. If the
menu, CLI, or web app need a new scanner option, add it to the shared runner
first and let each entry point pass it through.

## Scan Flow

The complete chain is:

```text
target -> naabu -> httpx -> nuclei -> vulnerability_report.md
```

In more detail:

1. `validate_scan_request` checks the target and common options before any
   process starts.
2. `build_naabu_command` creates the port discovery command.
3. `_extract_naabu_targets` parses `host:port` values for `httpx`.
4. `build_httpx_command` probes reachable HTTP services.
5. `_extract_http_urls` parses URLs for `nuclei`.
6. `parse_nuclei_findings` normalizes text, JSONL, or CSV output.
7. `summarize_scan_results` feeds the web app graphs.
8. `write_vulnerability_report` writes the human report.

Single-tool scans use the same command builders and parser helpers where
possible. This keeps behavior predictable and makes tests smaller.

## Safety Model

MTScan is a local operator tool. It still handles sensitive material:

- Authorization headers passed to `httpx` or `nuclei`
- Proxy URLs that may include credentials
- Interactsh tokens
- Nuclei variables
- Local filesystem paths in output directories

Do not print or return those values casually. Use `redact_command` for command
previews and keep API responses public by default. `src/app_server.py` should
return artifact names, not absolute local paths.

The web app is local-first:

- It binds to `127.0.0.1` by default.
- Non-loopback binds require `--allow-remote`.
- Host headers are checked.
- Static files are served only from `web/`.
- Browser security headers are sent for static and JSON responses.

If you add a route, keep the same posture: small request bodies, explicit JSON,
path normalization, and no raw local paths in responses.

## Output Contracts

Saved scan directories are intentionally simple:

```text
results_<target>_<timestamp>/
  naabu_results.txt|json|csv
  httpx_results.txt|json|csv
  nuclei_results.txt|jsonl|csv
  httpx_targets.txt
  nuclei_targets.txt
  vulnerability_report.md
```

Not every file exists for every scan. Code should check for file existence and
fall back to streamed output when it can.

`vulnerability_report.md` is the primary human artifact. Avoid creating
parallel report formats unless there is a clear user need. More files make
result folders harder to review.

## Storage Contract

The web app stores completed scan summaries, not raw scanner output.

Supported backends:

- `auto`: try Cassandra, then fall back to JSONL
- `cassandra`: require Cassandra
- `file`: use local JSONL
- `off`: disable history

The JSONL store is append-only. If the same scan id appears more than once,
readers should treat the later record as the fresher record.

Cassandra keeps a full record by id and a compact history table for listing.
When changing stored fields, keep `normalize_scan_record` backward-compatible
so old JSONL lines and old Cassandra rows still render in the app.

## Dependency Hygiene

Dependencies are pinned in `config/requirements.txt`. When changing them:

1. Prefer the smallest patch or minor bump that fixes the issue.
2. Run the unit tests.
3. Run `pip-audit -r config/requirements.txt` when available.
4. Check whether the GitHub code-scanning workflow also needs an update.
5. Note security-driven bumps in the PR or changelog text.

Do not add a dependency for convenience if the standard library keeps the code
clear enough. The web server intentionally avoids a framework so a fresh
scanner install has fewer moving parts.

## Local Verification

Fast checks:

```bash
python -m unittest discover -s tests -v
python -m compileall src commands tests install
python -m py_compile mtscan.py install/setup.py
```

Useful dry runs:

```bash
python src/workflow.py --dry-run --all -host example.com --top-ports 10 --save-output --json-output
python src/workflow.py --dry-run -nuclei -host https://example.com --severity critical,high --save-output --json-output
python src/app_server.py --host 127.0.0.1 --port 8765
```

Optional security checks when installed:

```bash
pip-audit -r config/requirements.txt
bandit -r commands install src tests mtscan.py --severity-level medium --confidence-level medium
semgrep scan --config p/default --config p/security-audit --config p/secrets .
```

## Change Checklist

Before handing off a change, check:

- Targets and scanner options are validated before process execution.
- Commands are built as lists, not shell strings.
- Sensitive command values are redacted in reports, API responses, and menu
  previews.
- Absolute local paths are not exposed through the web API.
- Dry-run output is useful and does not point to files that dry-run never
  creates.
- The report still separates security findings from informational observations.
- New behavior has a focused regression test.
- README or docs link to the new behavior if a user needs to know about it.

## Common Changes

Adding a scanner flag:

1. Add the option to the relevant `build_*_command` function.
2. Add validation in `validate_scan_options` if the value has a known shape.
3. Pass it through `src/workflow.py`.
4. Add it to `mtscan.py` or `src/app_server.py` only if that entry point should
   expose it.
5. Update redaction sets if the value can contain secrets or local paths.
6. Add a command-builder or report-redaction test.

Changing report output:

1. Update `summarize_scan_results` if the web app needs the same data.
2. Update `write_vulnerability_report`.
3. Add a test with a tiny scanner fixture.
4. Keep the report readable without raw scanner context.

Changing web app data:

1. Keep `public_summary` and `public_scan_record` restrictive.
2. Update storage normalization if persisted records need the new field.
3. Add tests around redaction or public shape.
4. Manually open the app and check the empty state and a dry-run scan.

## Release Notes Template

Use short, operator-centered notes:

```text
Changed
- Improved dry-run chain previews so nuclei uses a direct target.

Fixed
- Redacted short-form nuclei secret flags in reports and menu previews.

Security
- Bumped requests and Jinja2 pins to patched versions.

Verification
- python -m unittest discover -s tests -v
- python -m compileall src commands tests install
```

