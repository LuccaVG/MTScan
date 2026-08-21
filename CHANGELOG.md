# Changelog

All notable user-visible changes to MTScan are documented in this file.

The format follows **Keep a Changelog**, and version numbers follow **Semantic Versioning**.

## [Unreleased]

## [1.0.2] - 2026-08-21

### Changed

- CLI public-connectivity validation is now target-aware for explicitly non-public scan targets.
- Loopback, private/link-local IPs and CIDRs, IPv6 unique-local targets, and `localhost` no longer require `--skip-network-check` for ordinary scans.
- Operations that explicitly require public connectivity, such as `--update-templates`, continue to run the connectivity check even when the scan target is private.

### Tests

- Added regression coverage for loopback, RFC1918, IPv6 unique-local, localhost, public-target classification, noninteractive private-target scans, and the template-update connectivity exception.

## [1.0.1] - 2026-08-21

### Changed

- Updated MTScan's ProjectDiscovery command compatibility layer for current HTTPX and Nuclei CLI behavior.
- Built-in web scan profiles no longer apply restrictive positive Nuclei tag filters that could silently exclude CVE/RCE and other vulnerability templates.
- Raw Naabu, HTTPX, and Nuclei result files are retained as scan evidence while transient chain handoff lists are removed.

### Fixed

- HTTPX `--method` now maps to upstream `-x` request-method selection instead of the unrelated `-method` output probe.
- Nuclei excluded tags now map to `-etags`; `-et` remains upstream's exclude-template flag.
- Nuclei maximum redirects now map to `-mr` instead of the obsolete/incorrect `-maxr` form.
- Nuclei custom User-Agent values are passed through `-H "User-Agent: ..."`.
- Unsupported Nuclei CSV requests now fail validation rather than generating an invalid `-csv` command.
- Scan target validation rejects embedded URL credentials, invalid ports, malformed CIDRs, and malformed hostnames.
- Command previews defensively redact URL userinfo.

### Tests

- Added regression coverage for current ProjectDiscovery flag generation, target validation, URL redaction, Nuclei profile filtering, and raw evidence retention.
- Compatibility transformations were exercised in a disposable local harness. Full real-binary compatibility remains dependent on an environment containing upstream ProjectDiscovery binaries.

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

### Fixed

- URL target handling for chained scanner propagation is covered by regression tests.
- Bandit findings related to hardcoded default credentials and unrestricted URL opening were removed from the supported code path.
- CodeQL incomplete URL substring sanitization logic was replaced with structural command checks.

### Security

- First-run web credentials use a cryptographically random one-time password instead of a hardcoded default password.
- Mandatory first-login password change is enforced before protected API use.
- Host-header checks, defensive browser headers, request-size limits, static-path validation, and API redaction are enabled in the local web server.

[Unreleased]: https://github.com/LuccaVG/MTScan/compare/v1.0.2...develop
[1.0.2]: https://github.com/LuccaVG/MTScan/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/LuccaVG/MTScan/compare/v1.0.0-alpha...v1.0.1
[1.0.0-alpha]: https://github.com/LuccaVG/MTScan/releases/tag/v1.0.0-alpha
