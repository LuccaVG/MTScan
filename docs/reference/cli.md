# CLI Reference

The primary command-line entry point is:

```bash
python src/workflow.py [options] [target]
```

`-host` / `--host` may be used instead of the positional target.

## Target and mode selection

| Flag | Type | Description | Default |
|---|---|---|---|
| `target` | positional | IP, hostname, CIDR, host:port, or HTTP(S) URL | none |
| `-host`, `--host` | string | Explicit scan target | none |
| `-naabu`, `--naabu` | boolean | Run Naabu only | off |
| `-httpx`, `--httpx` | boolean | Run HTTPX only | off |
| `-nuclei`, `--nuclei` | boolean | Run Nuclei only | off |
| `--all`, `--chain` | boolean | Run Naabu -> HTTPX -> Nuclei | off |

At least one tool mode and one target are required unless `--check-tools` is used.

## Naabu options

| Flag | Type | Description | Default |
|---|---|---|---|
| `-p`, `--ports` | string | Port list/range, `all`, or `top-N` | none |
| `--top-ports` | integer | Number of top ports | `1000` when no port option is set |
| `--threads` | integer | Naabu concurrency | upstream/default unless preset |
| `--rate` | integer | Packet rate | upstream/default unless preset |
| `--exclude-ports` | string | Ports to exclude | none |
| `--scan-type` | `syn` or `connect` | Naabu scan type | `connect` in MTScan command construction |
| `--naabu-timeout` | integer | Naabu probe timeout | upstream/default |
| `--naabu-retries` | integer | Naabu retries | upstream/default |
| `--naabu-json` | boolean | Request Naabu JSON | off |
| `--naabu-csv` | boolean | Request Naabu CSV | off |

Compatibility-only accepted flags: `--source-port`, `--interface`, `--host-discovery`, `--ping`, `--no-ping`, and `--naabu-debug`. They are accepted by the MTScan parser but are not currently guaranteed to change the constructed Naabu command.

## HTTPX options

| Flag | Type | Description | Default |
|---|---|---|---|
| `--title` | boolean | Extract page title | off for single-tool CLI; enabled by `--all` |
| `--status-code` | boolean | Show status code | off for single-tool CLI; enabled by `--all` |
| `--tech-detect` | boolean | Detect technologies | off for single-tool CLI; enabled by `--all` |
| `--web-server` | boolean | Show server header | off for single-tool CLI; enabled by `--all` |
| `--follow-redirects` | boolean | Follow redirects | off |
| `--rate-limit` | integer | HTTPX request rate | upstream/default |
| `--headers` | comma-separated string | Custom HTTP headers | none |
| `--content-length` | boolean | Show response length | off |
| `--response-time` | boolean | Show response time | off |
| `--httpx-timeout` | integer | HTTPX timeout | upstream/default |
| `--httpx-threads` | integer | HTTPX threads | upstream/default |
| `--method` | string | HTTP request method; mapped to current HTTPX `-x` | upstream/default |
| `--user-agent` | string | Custom HTTPX User-Agent | none |
| `--filter-code` | string | Filter status codes | none |
| `--filter-length` | string | Filter response lengths | none |
| `--match-code` | string | Match status codes | none |
| `--match-length` | string | Match response lengths | none |
| `--httpx-json` | boolean | Request HTTPX JSON | off |
| `--httpx-csv` | boolean | Request HTTPX CSV | off |

`--httpx-retries` is accepted for compatibility but is not currently guaranteed to affect the constructed HTTPX command.

## Nuclei options

| Flag | Type | Description | Default |
|---|---|---|---|
| `-t`, `--templates` | string | Template or template directory selection | Nuclei default set |
| `--template-path` | string | Alternate template path input | none |
| `--tags` | string | Include template tags | none |
| `--severity` | comma-separated values | Severity filter | Nuclei default for CLI; web profiles set their own filters |
| `--exclude-tags` | string | Exclude template tags; mapped to current Nuclei `-etags` | none |
| `--exclude-templates` | string | Exclude templates | none |
| `--exclude-matchers` | string | Exclude matcher names | none |
| `--concurrency` | integer | Nuclei template concurrency | upstream/default |
| `--parallel-processing` | integer | Nuclei bulk size | upstream/default |
| `--nuclei-rate-limit` | integer | Nuclei request rate | upstream/default |
| `--nuclei-timeout` | integer | Per-request Nuclei timeout | upstream/default |
| `--nuclei-retries` | integer | Nuclei retries | upstream/default |
| `--proxy` | string | HTTP proxy | none |
| `--disable-redirects` | boolean | Disable Nuclei redirects | off |
| `--max-redirects` | integer | Maximum redirects; mapped to current Nuclei `-mr` | upstream/default |
| `--nuclei-user-agent` | string | Nuclei User-Agent, sent as an HTTP `User-Agent` header | none |
| `--custom-headers` | string | Nuclei headers | none |
| `--vars` | string | Nuclei variables | none |
| `--store-resp` | boolean | Store Nuclei responses | off |
| `--store-resp-dir` | path | Stored response directory | Nuclei default if enabled |
| `--interactsh-server` | string | Custom Interactsh server | none |
| `--no-interactsh` | boolean | Disable Interactsh | off in CLI; enabled by built-in web profiles |
| `--interactsh-token` | string | Interactsh token | none |
| `--nuclei-json` | boolean | Request Nuclei JSONL | off |
| `--markdown-export` | path | Nuclei Markdown export directory | none |
| `--sarif-export` | path | Nuclei SARIF export file | none |

`--nuclei-csv` may still be accepted by older parser surfaces, but MTScan 1.0.1 rejects it before execution because current ProjectDiscovery Nuclei does not support CSV output. Use `--nuclei-json` or `--json-output` for structured Nuclei results.

Compatibility-only accepted flags: `--exclude-severity` and `--include-rr`.

## ProjectDiscovery compatibility notes

MTScan 1.0.1 aligns command construction with the current ProjectDiscovery CLI semantics used by the project:

- HTTPX request methods use `-x`; upstream `-method` is an output/display probe and is not used for MTScan's `--method` selector.
- Nuclei exclude-tag filtering uses `-etags`; upstream `-et` is reserved for excluded templates.
- Nuclei maximum redirects use `-mr`.
- Nuclei User-Agent overrides are emitted through `-H "User-Agent: ..."`.
- Unsupported Nuclei CSV output fails validation rather than generating an invalid scanner command.

These mappings are covered by regression tests because ProjectDiscovery CLI behavior can change independently of MTScan.

## Global execution and output options

| Flag | Type | Description | Default |
|---|---|---|---|
| `--tool-silent` | boolean | Ask scanners for essential output only | off |
| `-s`, `--stealth` | boolean | Apply conservative rates/concurrency and disable Interactsh | off |
| `-o`, `--output-dir` | path | Result directory | generated timestamped directory when saving |
| `--save-output` | boolean | Generate a saved report for individual-tool mode | off; implied by `--all` |
| `--json-output` | boolean | Request structured scanner output for parsing | off |
| `--update-templates` | boolean | Update Nuclei templates before scanning | off |
| `--timeout` | integer | Per-tool/process runtime cap where applicable | none |
| `--force-tools` | boolean | Continue when preflight tool checks fail | off |
| `--skip-network-check` | boolean | Skip Internet/network preflight | off |
| `--dry-run` | boolean | Validate and print commands without scanner execution | off |
| `--check-tools` | boolean | Check Naabu/HTTPX/Nuclei availability and exit | off |
| `--no-color` | boolean | Disable scanner color output | off at CLI level; MTScan command builders generally request no color |

`--verbose` is accepted for compatibility and is not currently a stable behavior switch.

---

## `--severity`

### Description

Filters Nuclei findings by severity before Nuclei runs.

### Syntax

```bash
python src/workflow.py --nuclei \
  -host https://target.example \
  --severity critical,high
```

### Accepted values

- `critical`
- `high`
- `medium`
- `low`
- `info`
- `unknown`

Values may be comma-separated.

### Default

The CLI does not impose a severity filter unless a caller/profile supplies one. Built-in web profiles use explicit severity sets.

### Notes

A severity filter changes which Nuclei templates/results are considered. It does not change MTScan's interpretation of a finding's reported severity.

## `--json-output`

### Description

Requests structured JSON/JSONL scanner output where supported so MTScan can parse richer metadata.

### Syntax

```bash
python src/workflow.py --all -host target.example --json-output
```

### Default

Disabled for the CLI. The web app defaults new scan jobs to structured output.

### Notes

This is a parsing mode, not a guarantee of a retained raw JSON artifact. See [Output formats](output-formats.md).

## `--dry-run`

### Description

Validates the scan request and prints redacted commands without running the scanners.

### Syntax

```bash
python src/workflow.py --all -host https://example.com --dry-run
```

### Default

Disabled.

### Notes

Dry runs do not persist scan history and do not prove that the scanners or target will succeed in a live run.
