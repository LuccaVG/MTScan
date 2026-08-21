# Runtime validation

MTScan's runtime validation complements the unit and security workflows by exercising the CLI and local web application as running processes.

The runtime workflow uses isolated ProjectDiscovery-compatible scanner stubs. It does not scan public networks and does not claim vulnerability detection. Its purpose is to validate MTScan orchestration, API behavior, authentication, report generation, and browser-facing security controls.

The web application checks cover static dashboard delivery, defensive HTTP headers, first-run credentials, mandatory password change, authenticated health access, Host-header filtering, static path-traversal rejection, JSON content-type validation, dry-run scans, a complete Naabu to HTTPX to Nuclei chain, overview aggregation, schedule creation/update/deletion, logout, and login with the changed password.

The CLI checks cover help output, URL dry-run handling, local/private target execution without a public-connectivity requirement, chained scanner orchestration, report generation, and retention of raw scanner evidence.

A passing runtime workflow is integration evidence only. Real ProjectDiscovery binary compatibility and real vulnerable-target detection remain separate test categories.
