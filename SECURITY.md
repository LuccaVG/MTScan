# Security Policy

MTScan is a security testing tool and must be used only on systems you own or are explicitly authorized to assess.

## Supported versions

| Version | Supported |
|---|---|
| `1.0.2-alpha` / current `develop` alpha line | Yes |
| Older development snapshots | No guaranteed security support |

During the alpha period, security fixes are applied to the current development line. Backports are not guaranteed.

## Security contact and responsible disclosure

Preferred reporting method: **GitHub private vulnerability reporting / Security Advisories** for this repository.

Maintainer: **@LuccaVG**.

If private vulnerability reporting is unavailable, open a minimal public issue asking for a private contact channel **without including exploit details, secrets, or reproduction data**.

Do not publish a proof of concept or exploitation details before coordinated disclosure.

## Expected response process

These are target response times, not service-level guarantees:

| Stage | Target |
|---|---:|
| Acknowledge report | 7 days |
| Initial triage | 14 days |
| Severity and scope decision | 21 days |
| Remediation plan or status update | 30 days |

Complex dependency or architectural issues may require more time. The reporter should receive a status update when the initial target cannot be met.

## In scope

Examples include:

- Authentication or authorization bypass in the local web app.
- Session or password handling weaknesses.
- Host-header, path traversal, file write, or static-file escape issues.
- Command injection or unsafe subprocess construction.
- Target-validation bypasses that cause unintended scanner behavior.
- Leakage of credentials, tokens, headers, proxy values, local paths, or private scan data.
- Unsafe report or API serialization.
- Installer behavior that exposes secrets or performs unexpected privileged writes.
- Dependency vulnerabilities that are reachable in MTScan's supported execution paths.
- Unsafe handling of untrusted Nuclei templates.

## Out of scope

The following are generally not MTScan vulnerabilities:

- Vulnerabilities found by Naabu, HTTPX, or Nuclei in a third-party target.
- False positives or false negatives caused solely by upstream scanner templates, unless MTScan corrupts or misrepresents the result.
- Issues requiring an attacker to already control the operating system account running MTScan with equivalent privileges.
- Denial of service caused by intentionally scanning an unauthorized or fragile third-party target.
- Upstream vulnerabilities that do not affect a version or code path used by MTScan.

## Safe testing expectations

- Prefer loopback, disposable VMs, containers, and isolated lab networks.
- Do not test security reports against public third-party systems without authorization.
- Use non-production credentials and synthetic data.
- Keep scan rates low when availability is part of the test.
- Avoid destructive Nuclei templates or templates that execute code unless the lab is explicitly designed for that purpose.
- Do not attach raw private scan results to public issues.

## Sensitive-data handling

MTScan attempts to redact sensitive command values and local paths from public command previews and API payloads. This does **not** mean every scanner response is safe to publish.

Scanner output and reports may contain:

- IP addresses and hostnames.
- URLs and internal paths.
- Service banners and software versions.
- CVE/CWE identifiers.
- Extracted response data.
- User-supplied headers or variables in upstream tool artifacts.

Treat result directories, history stores, Cassandra data, local authentication files, Nuclei stored responses, Markdown/SARIF exports, and screenshots as potentially sensitive.

## Dependency vulnerability policy

MTScan tracks Python dependency risk with `pip-audit`, Python code issues with Bandit, and source-level findings with CodeQL/Semgrep in GitHub Actions. Security-relevant dependency findings should be triaged for reachability and upgraded or mitigated when practical.

ProjectDiscovery binaries and Nuclei templates are external trusted dependencies. Keep them updated and verify their upstream source.

## Web application boundary

The web interface binds to loopback by default and refuses non-loopback binding unless `--allow-remote` is explicitly supplied. Remote binding changes the threat model and should be used only on a trusted lab network or behind an independently secured reverse proxy.

The local app uses an authenticated session cookie, a randomly generated first-run password, mandatory password change, Host-header restrictions, request-size limits, path traversal protection, CSP, `X-Frame-Options`, `nosniff`, and no-store caching.

## Nuclei template risk

A Nuclei template is not merely documentation. Templates can cause network requests and may use capabilities such as workflows, JavaScript, code execution, file access, or external interactions depending on Nuclei configuration and template type.

Only run templates from sources you trust and review custom templates before use. See [docs/concepts/security-model.md](docs/concepts/security-model.md).

## Authorization warning

Unauthorized scanning may be illegal, disruptive, or contractually prohibited. Define the target, ports, time window, rate, scanner profile, and allowed techniques before running MTScan.
