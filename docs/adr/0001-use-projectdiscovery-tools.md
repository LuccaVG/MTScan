# ADR-0001: Use ProjectDiscovery Tools

**Status:** Accepted  
**Date:** 2026-08-20

## Context

MTScan needs TCP discovery, HTTP service identification, and template-driven vulnerability checks. Reimplementing mature scanner engines would add large security, maintenance, and protocol-coverage burdens.

## Decision

MTScan will orchestrate ProjectDiscovery Naabu, HTTPX, and Nuclei as external binaries and keep MTScan focused on validation, safe command construction, stage handoff, result normalization, reporting, local UI, and history.

## Consequences

### Positive

- Reuses specialized maintained scanners.
- Keeps scanner behavior independently updatable.
- Allows MTScan to focus on orchestration and reporting.
- Nuclei provides a large template ecosystem and structured CVE metadata.

### Negative

- MTScan compatibility depends on upstream CLI behavior.
- Upstream binaries/templates are part of the trust boundary.
- Installation is larger than a pure-Python package.
- Reproducibility requires recording scanner and template versions.

## Alternatives considered

- Implement native port scanning, HTTP probing, and vulnerability signatures in Python.
- Embed scanner libraries directly.

Both would materially increase scope and maintenance cost.
