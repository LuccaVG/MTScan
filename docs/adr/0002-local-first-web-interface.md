# ADR-0002: Local-First Web Interface

**Status:** Accepted  
**Date:** 2026-08-20

## Context

A browser dashboard is useful for scans, schedules, history, findings, and assets, but an Internet-facing security-scanner control plane has a much larger attack surface.

## Decision

The MTScan web application binds to loopback by default. Non-loopback binding is refused unless the operator explicitly passes `--allow-remote`.

The bundled server will use session authentication, mandatory first-run password change, Host-header restrictions, request-size limits, static path validation, and defensive browser headers.

## Consequences

### Positive

- Reduces accidental exposure of a scanner control interface.
- Makes the secure default appropriate for a local security workstation/VM.
- Keeps deployment simple without requiring a web framework or reverse proxy.

### Negative

- Remote/team access requires deliberate additional architecture.
- The standard-library server is not intended to be a hardened public Internet service.
- Sessions are local/in-memory rather than a distributed authentication system.

## Alternatives considered

- Bind to `0.0.0.0` by default.
- Ship a public multi-user server.

Both were rejected for the alpha because they substantially expand the security model.
