# Continuous Integration

MTScan uses separate GitHub Actions workflows for functional tests and security analysis.

## Unit tests

`.github/workflows/tests.yml` runs the complete Python unittest suite on pushes to `develop` and `main`, on pull requests targeting `main`, and by manual dispatch.

The release gate command is:

```bash
python -m unittest discover -s tests -v
```

A release candidate should not be merged to `main` when this job fails.

## Security checks

`.github/workflows/code-scanning.yml` runs CodeQL, Semgrep, Bandit, dependency auditing, and dependency review where applicable.

Functional unit tests and security analysis are intentionally separate: passing one workflow does not imply that the other passed.

## 1.0.2 regression scope

MTScan 1.0.2 adds regression coverage for target-aware connectivity policy. Ordinary scans of explicitly non-public targets must not require public Internet connectivity, while operations that need Internet access, such as Nuclei template updates, must retain the connectivity preflight.
