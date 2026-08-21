# Continuous Integration

MTScan uses separate GitHub Actions workflows for unit tests, runtime integration, and security analysis.

## Unit tests

`.github/workflows/tests.yml` runs the complete Python unittest suite on pushes to `develop` and `main`, on pull requests targeting `main`, and by manual dispatch.

The release gate command is:

```bash
python -m unittest discover -s tests -v
```

A release candidate should not be merged to `main` when this job fails.

## Runtime validation

`.github/workflows/runtime-validation.yml` runs on pushes to `develop`, pull requests targeting `main`, and manual dispatch. It validates the CLI and starts the real MTScan web server on loopback for HTTP-level end-to-end checks.

The workflow covers CLI help and dry-run behavior, local chained execution and report/evidence retention, webapp startup, authentication and mandatory password change, defensive HTTP headers, Host-header filtering, static-path traversal rejection, scan APIs, overview data, schedule CRUD, logout/relogin, and full Naabu -> HTTPX -> Nuclei orchestration.

Scanner execution in this workflow uses isolated ProjectDiscovery-compatible stubs. This validates MTScan orchestration and web/API behavior without sending vulnerability-scanning traffic; it does not replace separate compatibility testing with real ProjectDiscovery binaries or isolated real-CVE lab testing.

See [Runtime validation](runtime-validation.md) for the detailed scope and limitations.

## Security checks

`.github/workflows/code-scanning.yml` runs CodeQL for Python and JavaScript/TypeScript, Semgrep, Bandit, Python dependency auditing, and dependency review where applicable.

Unit, runtime, and security workflows are independent gates. Passing one does not imply that the others passed.

## 1.0.2 regression scope

MTScan 1.0.2 adds regression coverage for target-aware connectivity policy. Ordinary scans of explicitly non-public targets must not require public Internet connectivity, while operations that need Internet access, such as Nuclei template updates, must retain the connectivity preflight.

The 1.0.2 validation baseline also includes the complete 37-test Python suite and the loopback webapp runtime checks described above.
