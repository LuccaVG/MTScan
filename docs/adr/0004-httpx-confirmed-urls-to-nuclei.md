# ADR-0004: Nuclei Receives Only HTTPX-Confirmed URLs in Live Chains

**Status:** Accepted  
**Date:** 2026-08-20

## Context

Naabu discovers TCP services, but not every TCP service speaks HTTP. Sending every discovered port directly to the HTTP-focused vulnerability stage produces meaningless requests against services such as SSH, FTP, SMTP, and databases.

## Decision

During a live chained scan:

1. Naabu discovers TCP endpoints.
2. HTTPX probes those endpoints.
3. MTScan extracts only `http://` and `https://` URLs confirmed by HTTPX.
4. Nuclei receives that confirmed URL list.
5. If HTTPX confirms no HTTP(S) URLs, Nuclei is skipped for the chain.

Dry-run mode may synthesize a preview target because no live HTTPX result exists.

## Consequences

### Positive

- Avoids meaningless HTTP vulnerability requests against non-HTTP services.
- Reduces noise and cleaner finding context.
- Gives Nuclei concrete schemes and endpoints.
- Makes Naabu -> HTTPX -> Nuclei propagation explicit and testable.

### Negative

- Non-HTTP vulnerabilities are outside the current chained Nuclei stage.
- HTTPX false negatives can prevent a service from reaching Nuclei.
- Specialized Nuclei TCP/DNS/etc. templates require an explicit non-chain workflow rather than automatic propagation.

## Alternatives considered

- Pass every Naabu `host:port` directly to Nuclei.
- Run Nuclei against both HTTP and HTTPS guesses for every open port.

Both alternatives increase noise and weaken the semantic boundary between discovery and HTTP vulnerability assessment.
