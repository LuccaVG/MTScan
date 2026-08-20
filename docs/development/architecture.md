# Development Architecture

This page describes module ownership for contributors. For the user-facing model, see [Conceptual architecture](../concepts/architecture.md).

## Module responsibilities

### `src/tool_runner.py`

Owns the scanner abstraction. Changes to target validation, command builders, executable discovery, stage propagation, scanner output parsing, CVE extraction, redaction, report generation, or output cleanup belong here.

CLI, web, and wrappers should not duplicate scanner command construction.

### `src/workflow.py`

Owns CLI parsing and orchestration policy around the shared runner: tool selection, preflight, dry-run behavior, top-level exit codes, template update requests, and CLI history persistence.

### `src/app_server.py`

Owns the HTTP/session layer, web scan profiles, API validation, in-memory jobs, schedules, local security headers, authentication, and static-file serving. It should call the shared runner rather than shelling out to `workflow.py`.

### `src/scan_storage.py`

Owns persistence adapters and normalized stored records. Backends must expose equivalent app-level behavior for scan history, schedules, auth, and health status.

### `web/`

Contains static browser assets. The browser should treat the local API as the source of scan state and should not receive sensitive local filesystem paths.

### `install/setup.py`

Owns privileged platform setup. Changes here require extra scrutiny because they execute package managers, write system paths, install tools, and manage services.

## Dependency direction

```text
web browser -> app_server -> tool_runner -> external scanners
                        \-> scan_storage
workflow CLI ----------> tool_runner
              \--------> scan_storage
interactive menu ------> app_server / management helpers
```

Avoid introducing a reverse dependency from `tool_runner` into the web layer.

## Cross-cutting rules

- Validation before execution.
- Argument-list subprocesses rather than shell command strings.
- Redaction before data crosses into reports/API.
- Scanner-specific parsing remains centralized.
- Storage records are normalized before persistence.
- Security-sensitive changes require regression tests.
- Architectural constraints are recorded as ADRs.
