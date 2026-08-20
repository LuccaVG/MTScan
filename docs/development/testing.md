# Testing

MTScan testing is divided into explicit categories so a passing test is not overstated.

## Test categories

### Unit tests

Validate isolated functions and data transformations, such as target validation, redaction, parser behavior, and report normalization.

```bash
python3 -m unittest discover -s tests -v
```

### Integration tests

Validate multiple MTScan components together, such as CLI -> shared runner -> scanner process -> report generation, or web API -> job runner -> storage.

### Regression tests

Capture a previously observed defect so it does not silently return. Examples include URL target propagation, authentication defaults, output cleanup behavior, and scanner handoff.

### Security tests

Validate security controls such as Bandit/CodeQL/Semgrep findings, dependency auditing, authentication behavior, Host-header restrictions, path traversal defenses, redaction, and validation bypasses.

### Local lab tests

Run MTScan against loopback or isolated fixtures. A local fixture test is not proof of compatibility with a real vulnerable appliance or VM.

### Real-tool compatibility tests

Use actual upstream Naabu/HTTPX/Nuclei binaries while keeping the target controlled. Record exact upstream versions because their CLI behavior changes independently of MTScan.

## Test record template

```text
Test ID:
Purpose:
Environment:
MTScan commit/version:
Dependencies:
Target:
Network isolation:
Command:
Expected result:
Actual result:
Pass/fail:
Known limitations:
```

## Recorded integration/regression lab tests — 2026-08-20

### INT-CHAIN-001

**Purpose:** Validate CLI/web orchestration, target propagation, report generation, authentication flow, and full Naabu -> HTTPX -> Nuclei control flow in an isolated runner.

**Environment:** GitHub-hosted Ubuntu 24.04.4 LTS, Python 3.12.

**MTScan base:** `develop` around commit `39ff92712877eb3b6d144e37e9a198a3a1d3f821`; temporary test-only PR was not merged.

**Dependencies:** MTScan Python dependencies; scanner executable stubs that emulated ProjectDiscovery version probes, output, and `-o` file creation.

**Target:** Loopback fixture / synthetic scanner output.

**Network isolation:** No external vulnerability target was scanned.

**Expected result:** CLI help/dry-run succeeds; interactive launcher starts; full chain propagates stage outputs; web app authenticates; password change is enforced; health and scan APIs work; report is generated.

**Actual result:** PASS after correcting the test harness to emulate scanner output-file creation.

**Known limitations:** This test did **not** use real scanner binaries and is not Metasploitable or CVE compatibility certification.

### INT-HTTPX-001

**Purpose:** Validate real ProjectDiscovery HTTPX execution through MTScan against a live local web server.

**Environment:** GitHub-hosted Ubuntu 24.04.4 LTS, Python 3.12, Go 1.27.0.

**MTScan base:** `develop` commit `39ff92712877eb3b6d144e37e9a198a3a1d3f821`; temporary test-only PR was not merged.

**Dependencies:** ProjectDiscovery HTTPX `v1.10.0` installed from upstream Go module.

**Target:** `http://127.0.0.1:18080`, a Python `ThreadingHTTPServer` fixture.

**Network isolation:** Target bound to loopback only.

**Command:** MTScan `--httpx` with title/status/server collection and saved reporting.

**Expected result:** HTTPX reaches the service, returns HTTP 200 context, and MTScan reports one HTTP service.

**Actual result:** PASS.

**Known limitations:** The fixture was not intentionally vulnerable and validates HTTPX integration, not vulnerability detection.

### INT-CVE-001

**Purpose:** Validate real Nuclei CVE metadata detection plus MTScan CVE/CWE parsing and report generation.

**Environment:** Same isolated Ubuntu runner as INT-HTTPX-001.

**Dependencies:** Nuclei `v3.11.1`, Nuclei templates `v10.4.7`, custom safe local test template.

**Target:** `http://127.0.0.1:18080` with static test markers.

**Network isolation:** Loopback only.

**Expected result:** Real Nuclei matches the local template; output includes `CVE-2021-44228` and `CWE-917`; MTScan classifies one HIGH Known Vulnerability and adds the CVE to the report.

**Actual result:** PASS.

**Known limitations:** The server was **not** running vulnerable Log4j and the template did not exploit Log4Shell. This proves the Nuclei -> MTScan CVE metadata/reporting pipeline, not real-world exploitability of CVE-2021-44228.

## Security CI

The repository code-scanning workflow includes CodeQL, Semgrep, Bandit, and Python dependency auditing. These complement runtime tests; they do not replace them.

## Release test evidence

For release-critical integration tests, record the test ID, commit, environment, upstream scanner versions, sanitized logs, and result in the release notes or retained CI artifact. Do not keep sensitive customer evidence in public CI.
