# Coding and Documentation Standards

## Python style

Use readable Python 3 with explicit interfaces and minimal hidden behavior.

### PEP 257 docstrings

Public modules, classes, and functions should use PEP 257-style docstrings. Document arguments, return values, and raised exceptions when they are not obvious.

```python
def validate_target(target: object) -> str:
    """Validate and normalize a scan target.

    Args:
        target: IP address, hostname, CIDR range, host:port, or HTTP(S) URL.

    Returns:
        Normalized target string.

    Raises:
        ScanInputError: If the target format is invalid.
    """
```

### Type hints

New and materially changed public functions should have consistent type hints. Prefer concrete standard-library collection types already used by the project unless a refactor deliberately changes the type style.

### Subprocess safety

- Build scanner commands as argument lists.
- Do not introduce `shell=True` for user-influenced scanner commands.
- Validate targets and numeric/string options before execution.
- Keep scanner command construction centralized in `src/tool_runner.py`.
- Redact sensitive values before commands enter reports or API responses.

### Exceptions

Catch specific exceptions where practical. Bare `except:` clauses are not acceptable in new code. Broad `Exception` handlers should be limited to boundaries where failure must be converted into a stable user-facing error and should preserve useful diagnostics privately.

## Documentation structure

Use Diátaxis placement:

- `docs/getting-started/` — tutorials.
- `docs/how-to/` — task recipes.
- `docs/reference/` — factual interface documentation.
- `docs/concepts/` — explanation and design.
- `docs/development/` — contributor workflows.
- `docs/adr/` — architecture decisions.

Do not turn the root README into the complete manual.

## Technical page structure

A flag or command reference should consistently include Description, Syntax, Accepted values where relevant, Default, and Notes.

Example:

```markdown
## `--severity`

### Description

Filters Nuclei findings by severity.

### Syntax

```bash
python src/workflow.py --nuclei \
  -host https://target.example \
  --severity critical,high
```

### Accepted values

`critical`, `high`, `medium`, `low`, `info`, `unknown`.

### Default

No CLI-imposed filter.

### Notes

Document operational effects and limitations.
```

## Command examples

- Use `bash` fenced blocks for shell commands.
- Use placeholders such as `<authorized-target>` when a live example could encourage scanning a real third-party system.
- Use loopback for executable tutorials.
- State when a command is dry-run only.
- Never put real secrets in documentation.

## ADR format

Each ADR should contain:

```text
Title
Status
Date
Context
Decision
Consequences
Alternatives considered
```

ADRs are append-only historical decisions. Supersede an ADR with a new ADR rather than silently rewriting the reason for an old accepted decision.

## Changelog and versioning

User-visible changes must be reflected in `CHANGELOG.md`. Use canonical SemVer values from `VERSION`. See [release-process.md](release-process.md).

## Tests and documentation

When behavior changes, update tests and the relevant reference/concept page in the same change. Do not document a capability as certified unless the documented test environment actually exercised it.
