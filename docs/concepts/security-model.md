# Security Model and Threat Model

## Purpose

MTScan is an orchestration, validation, reporting, and local monitoring tool. It is **not** a vulnerability exploit framework and does not independently prove exploitability.

## Assets to protect

- Scanner authorization scope and target lists.
- Credentials, cookies, custom headers, proxy credentials, API keys, Interactsh tokens, and variables.
- Local filesystem paths and usernames.
- Scan results, service banners, CVE/CWE metadata, and extracted evidence.
- Authentication state for the local web application.
- Scan schedules and history.

## Trusted external binaries

MTScan trusts the installed ProjectDiscovery executables it invokes:

- `naabu`
- `httpx` / `httpx-toolkit`
- `nuclei`

Executable discovery checks common Linux paths and probes candidates with version/help arguments. This reduces accidental selection of an unrelated binary but does not provide cryptographic attestation of the executable.

Operators should install scanners from authoritative sources and protect the directories containing them from untrusted modification.

## Commands MTScan executes

Scanner commands are built as argument lists and executed without relying on shell command-string interpolation. MTScan also invokes installation/package-management commands in `install/setup.py`, which has a larger privileged trust surface.

Public command previews redact values associated with sensitive headers, proxies, tokens, variables, and path-bearing flags.

## Target validation

Targets are validated before execution. MTScan limits URL schemes to HTTP(S), rejects control/whitespace characters, validates CIDR prefix ranges, validates port expressions, bounds numeric options, and validates Nuclei severity/protocol values used by shared runner paths.

Validation is a syntactic safety boundary, not an authorization decision. MTScan cannot know whether the operator is permitted to scan the target.

## Network boundaries

### Scanner traffic

Naabu, HTTPX, and Nuclei generate outbound traffic according to their selected options. Nuclei templates may cause additional requests or interactions.

### Web interface

The web server binds to `127.0.0.1:8765` by default. A non-loopback bind is refused unless `--allow-remote` is explicitly set. Host-header restrictions are enforced unless remote mode permits broader host values.

Remote mode should be treated as a separate deployment model requiring network access controls and, where appropriate, a hardened reverse proxy/TLS layer.

## Authentication

The initial web username is `admin`. The first password is generated with a cryptographically secure random token when a new auth record is initialized and is printed to the local server console. The user must change it before protected API use.

Passwords are stored as derived hashes. Sessions are random server-side tokens held in memory and sent in the `mtscan_session` cookie. Server restarts invalidate in-memory sessions.

## Sensitive-data redaction

MTScan redacts known sensitive command values and replaces local path values with public-safe artifact names in API/report command previews.

Redaction is defense in depth, not a data-loss-prevention guarantee. Scanner response bodies, explicit Nuclei exports, stored responses, external tool logs, or unforeseen argument formats may contain sensitive information.

## Stored data

Depending on the backend, MTScan stores normalized scan history, schedules, and authentication state in Cassandra or local files. Reports can contain IPs, hostnames, URLs, software information, findings, CVEs, and remediation notes.

Explicit `--store-resp`, Markdown export, and SARIF export can retain additional raw evidence. Protect result directories and data stores with operating-system permissions appropriate to the environment.

## Privileges

Normal CLI/web scanner use should run with the minimum privileges required by the selected scanner behavior. Some Naabu scan modes may need elevated networking privileges depending on the platform.

`install/setup.py` is intentionally privileged and can modify packages, services, system paths, and repository configuration. Its threat model is different from normal unprivileged runtime use.

## Malicious Nuclei templates

Custom templates are trusted input. Depending on Nuclei capabilities, a template may perform network interactions, use external callbacks, execute JavaScript/code features, access files, or trigger state-changing application behavior.

MTScan does not sandbox templates. Review template source, disable unnecessary Interactsh behavior, and use isolated labs for potentially destructive or code-capable templates.

## CVE interpretation

MTScan extracts CVE identifiers from Nuclei metadata/output and links them to NVD. A reported CVE means the scanner matched a template associated with that identifier; it does not prove successful exploitation or guarantee the exact installed product/version is vulnerable.

## Threats intentionally not solved

- A fully compromised OS account running MTScan.
- Malicious replacement of trusted scanner binaries by an attacker with filesystem write access.
- Authorization/legal-scope determination.
- Guaranteed detection of every vulnerability.
- Sandboxing of arbitrary Nuclei templates.
- Public Internet hardening of the alpha web server.
