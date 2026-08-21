# MTScan Documentation

MTScan documentation follows the **Diátaxis** framework. Choose a section based on what you are trying to do rather than reading the documentation front to back.

## Getting started — guided learning

- [Installation](getting-started/installation.md)
- [Quickstart](getting-started/quickstart.md)
- [Your first scan](getting-started/first-scan.md)

## How-to guides — accomplish a task

- [Scan a single host](how-to/scan-single-host.md)
- [Scan a CIDR range](how-to/scan-cidr.md)
- [Use custom Nuclei templates](how-to/use-custom-nuclei-templates.md)
- [Use structured JSON mode](how-to/export-json.md)
- [Troubleshooting](how-to/troubleshooting.md)

## Reference — facts and interfaces

- [CLI reference](reference/cli.md)
- [Configuration](reference/configuration.md)
- [Output formats](reference/output-formats.md)
- [Exit codes](reference/exit-codes.md)
- [File layout](reference/file-layout.md)
- [Web API](reference/web-api.md)
- [Licensing](reference/licensing.md)

## Concepts — explanation and design

- [Architecture](concepts/architecture.md)
- [Scan workflow](concepts/scan-workflow.md)
- [Security model](concepts/security-model.md)
- [Limitations](concepts/limitations.md)

## Development — contributor documentation

- [Development architecture](development/architecture.md)
- [Testing](development/testing.md)
- [Continuous integration](development/ci.md)
- [Runtime validation](development/runtime-validation.md)
- [Release process](development/release-process.md)
- [Coding and documentation standards](development/coding-standards.md)

## Architecture Decision Records

- [ADR-0001: Use ProjectDiscovery tools](adr/0001-use-projectdiscovery-tools.md)
- [ADR-0002: Local-first web interface](adr/0002-local-first-web-interface.md)
- [ADR-0003: Report-oriented saved output](adr/0003-report-only-output.md)
- [ADR-0004: Nuclei receives only HTTPX-confirmed URLs in live chains](adr/0004-httpx-confirmed-urls-to-nuclei.md)

## Versioning

The current release is **1.0.2**. The root [`VERSION`](../VERSION) file is the canonical version source, and release history is maintained in the root [CHANGELOG.md](../CHANGELOG.md).
