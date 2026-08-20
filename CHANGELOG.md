# Changelog

All notable user-visible changes to MTScan are documented in this file.

The format follows **Keep a Changelog**, and version numbers follow **Semantic Versioning**. Pre-release labels use SemVer syntax; the human-facing name “1.0.0 Alpha” is represented as `1.0.0-alpha`.

## [Unreleased]

### Added

- Diátaxis documentation structure and Architecture Decision Records.

## [1.0.0-alpha] - 2026-08-20

### Added

- Shared Naabu, HTTPX, and Nuclei orchestration layer.
- Authenticated local web interface with scan history, schedules, findings, assets, and health status.
- Cassandra scan-history backend with local JSONL fallback.
- Remediation-focused `vulnerability_report.md` generation.
- CVE and CWE extraction from Nuclei findings, including NVD links in reports.
- CLI dry-run mode, scanner availability checks, and structured-output mode.
- GitHub code scanning with CodeQL, Semgrep, Bandit, and dependency auditing.

### Changed

- Live chained scans pass HTTP(S) targets confirmed by HTTPX to Nuclei.
- Command previews redact sensitive values and expose only public-safe path names.
- The web interface is local-first and requires explicit opt-in for remote binding.
- Saved scan reporting uses a report-oriented artifact model; scanner intermediates are used to build the report and cleaned up unless explicitly exported through an upstream tool option.

### Fixed

- URL target handling for chained scanner propagation is covered by regression tests.
- Bandit findings related to hardcoded default credentials and unrestricted URL opening were removed from the supported code path.
- CodeQL incomplete URL substring sanitization logic was replaced with structural command checks.

### Security

- First-run web credentials now use a cryptographically random one-time password instead of a hardcoded default password.
- Mandatory first-login password change is enforced before protected API use.
- Host-header checks, defensive browser headers, request-size limits, static-path validation, and API redaction are enabled in the local web server.

[Unreleased]: https://github.com/LuccaVG/MTScan/compare/v1.0.0-alpha...develop
[1.0.0-alpha]: https://github.com/LuccaVG/MTScan/releases/tag/v1.0.0-alpha
