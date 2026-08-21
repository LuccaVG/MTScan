# Testing

MTScan testing is divided into explicit categories so a passing test is not overstated.

## Test categories

### Unit tests

Validate isolated functions and data transformations, such as target validation, redaction, parser behavior, report normalization, and scanner command construction.

```bash
python -m unittest discover -s tests -v
```

### Integration tests

Validate multiple MTScan components together, such as CLI -> shared runner -> scanner process -> report generation, or web API -> job runner -> storage.

### Regression tests

Capture a previously observed defect so it does not silently return. Examples include URL target propagation, authentication defaults, output cleanup behavior, scanner handoff, and upstream CLI flag compatibility.

### Security tests

Validate security controls such as authentication behavior, Host-header restrictions, path traversal defenses, redaction, and validation bypasses.

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

## Recorded compatibility validation — 2026-08-21

### COMPAT-PD-001

**Purpose:** Validate MTScan 1.0.1 command construction against current ProjectDiscovery HTTPX and Nuclei CLI semantics after the compatibility patch.

**MTScan branch:** `develop`.

**Compatibility checks:**

- HTTPX `--method POST` produces upstream request-method selection with `-x POST` and does not use the unrelated `-method` display probe.
- Nuclei `--exclude-tags` produces `-etags` rather than `-et`.
- Nuclei `--max-redirects` produces `-mr` rather than `-maxr`.
- Nuclei User-Agent overrides produce `-H "User-Agent: ..."` rather than `-user-agent`.
- Nuclei CSV mode is rejected before execution because current upstream Nuclei does not provide CSV output.
- Earlier target-validation, command-redaction, profile-filter, URL-to-Naabu, and raw-evidence behaviors remain covered by regression tests.

**Expected result:** MTScan produces only supported current ProjectDiscovery flag forms for the affected options and fails closed for unsupported Nuclei CSV output.

**Actual result:** PASS in a focused disposable local compatibility harness. Equivalent regression cases are retained in `tests/test_regressions.py`.

**Known limitation:** The execution runner used for this validation did not contain downloadable/current ProjectDiscovery binaries and had no outbound network path. This record certifies MTScan's command construction against the documented upstream CLI contract; it does not replace a later real-binary compatibility run.

## Recorded integration/regression lab tests — 2026-08-20

### INT-CHAIN-001

**Purpose:** Validate CLI/web orchestration, target propagation, report generation, authentication flow, and full Naabu -> HTTPX -> Nuclei control flow in an isolated runner.

**Environment:** Ubuntu 24.04.4 LTS, Python 3.12.

**Dependencies:** MTScan Python dependencies; scanner executable stubs that emulated ProjectDiscovery version probes, output, and `-o` file creation.

**Target:** Loopback fixture / synthetic scanner output.

**Network isolation:** No external vulnerability target was scanned.

**Actual result:** PASS after correcting the test harness to emulate scanner output-file creation.

**Known limitations:** This test did **not** use real scanner binaries and is not Metasploitable or CVE compatibility certification.

### INT-HTTPX-001

**Purpose:** Validate real ProjectDiscovery HTTPX execution through MTScan against a live local web server.

**Environment:** Ubuntu 24.04.4 LTS, Python 3.12, Go 1.27.0.

**Dependencies:** ProjectDiscovery HTTPX `v1.10.0` installed from upstream Go module.

**Target:** `http://127.0.0.1:18080`, a Python `ThreadingHTTPServer` fixture.

**Network isolation:** Target bound to loopback only.

**Expected result:** HTTPX reaches the service, returns HTTP 200 context, and MTScan reports one HTTP service.

**Actual result:** PASS.

**Known limitations:** The fixture was not intentionally vulnerable and validates HTTPX integration, not vulnerability detection.

### INT-CVE-001

**Purpose:** Validate real Nuclei CVE metadata detection plus MTScan CVE/CWE parsing and report generation.

**Dependencies:** Nuclei `v3.11.1`, Nuclei templates `v10.4.7`, custom safe local test template.

**Target:** `http://127.0.0.1:18080` with static test markers.

**Network isolation:** Loopback only.

**Expected result:** Real Nuclei matches the local template; output includes `CVE-2021-44228` and `CWE-917`; MTScan classifies one HIGH Known Vulnerability and adds the CVE to the report.

**Actual result:** PASS.

**Known limitations:** The server was **not** running vulnerable Log4j and the template did not exploit Log4Shell. This proves the Nuclei -> MTScan CVE metadata/reporting pipeline, not real-world exploitability of CVE-2021-44228.

## Release test evidence

For release-critical integration tests, record the test ID, commit, environment, upstream scanner versions, sanitized logs, and result. Do not keep sensitive customer evidence in public test records.
