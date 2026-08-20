# File Layout

```text
MTScan/
├── .github/                 GitHub Actions and repository automation
├── commands/                compatibility/helper command modules
├── config/                  runtime requirements and installer-generated config
├── data/                    local runtime state (generated)
├── docs/                    Diátaxis documentation
│   ├── getting-started/
│   ├── how-to/
│   ├── reference/
│   ├── concepts/
│   ├── development/
│   └── adr/
├── install/
│   └── setup.py             privileged installer/orchestrator
├── licenses/                third-party/project license texts and notices
├── src/
│   ├── app_server.py        local web server and API
│   ├── scan_storage.py      Cassandra / file storage abstraction
│   ├── tool_runner.py       scanner validation, execution, parsing, reporting
│   └── workflow.py          CLI entry point
├── tests/                   unit/regression fixtures and tests
├── web/                     static browser application
├── mtscan.py                interactive launcher
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── VERSION
```

## Generated result directories

When an output directory is not specified, MTScan derives a timestamped directory from the target, for example:

```text
results_target.example_20260820_120000/
```

The canonical retained report is:

```text
vulnerability_report.md
```

Intermediate scanner and handoff files may exist while a scan is running but are not a stable retained interface. See [Output formats](output-formats.md).

## Local data files

With the file backend, defaults are:

```text
data/scan_history.jsonl
data/schedules.json
data/auth.json
```

These files may contain sensitive operational metadata and should not be published.
