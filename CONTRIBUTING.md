# Contributing to MTScan

Contributions are welcome when they improve defensive security testing, reliability, documentation, reporting, or the safety of the local application.

## Before contributing

Use MTScan only for authorized security testing. Do not place real credentials, tokens, customer data, private scan output, or third-party target data in issues, pull requests, tests, screenshots, or fixtures.

Security vulnerabilities in MTScan itself must follow [SECURITY.md](SECURITY.md), not the public issue workflow.

## Development branch

Normal development changes should target `develop`. Release preparation is promoted from `develop` according to [docs/development/release-process.md](docs/development/release-process.md).

## Development setup

Install Python dependencies:

```bash
python -m pip install -r config/requirements.txt
```

Check syntax:

```bash
python -m py_compile mtscan.py install/setup.py src/workflow.py src/tool_runner.py src/app_server.py src/scan_storage.py
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

Preview the chain without network traffic:

```bash
python src/workflow.py --all -host https://example.com --dry-run --json-output
```

## Code standards

Python changes should follow the rules in [coding-standards.md](docs/development/coding-standards.md). In particular:

- Use PEP 257-style docstrings for public modules, classes, and functions.
- Add type hints to new or materially changed Python interfaces.
- Pass subprocess arguments as lists; do not introduce `shell=True` for scanner execution.
- Validate user-controlled targets and options before constructing scanner commands.
- Redact credentials, tokens, headers, proxy secrets, and local paths from public command previews.
- Add tests for security-sensitive parsing, redaction, path handling, command construction, and target propagation.

## Documentation standards

MTScan documentation uses Diátaxis:

- **Tutorials / getting started** teach by guided execution.
- **How-to guides** solve a specific task.
- **Reference** documents facts, flags, files, configuration, formats, and APIs.
- **Explanation / concepts** documents architecture, trade-offs, security boundaries, and limitations.

Documentation changes should use consistent headings, tested commands, explicit defaults, and links to related reference pages. Architecture decisions that constrain future behavior should be recorded under `docs/adr/`.

## Testing requirements

Choose the appropriate test category and document the environment for non-trivial scanner changes. The test taxonomy is defined in [docs/development/testing.md](docs/development/testing.md).

Do not describe a loopback fixture or scanner stub test as compatibility certification for a real vulnerable VM, product, CVE, or external environment.

## Pull requests

A pull request should explain:

1. What changed.
2. Why it changed.
3. Security or compatibility impact.
4. Tests performed and their environment.
5. Documentation and changelog impact.

Update `CHANGELOG.md` for user-visible changes. Breaking changes require a major version decision; features require a minor version decision; backward-compatible fixes require a patch decision once MTScan reaches stable SemVer releases.

## Licensing of contributions

Unless a separate written agreement says otherwise, contributions submitted to this repository are offered under the same project multi-license grant:

```text
Apache-2.0 OR MIT OR BSD-3-Clause
```

Third-party tools, templates, binaries, dependencies, names, logos, and trademarks are not relicensed by MTScan. Do not add redistributed third-party material unless its license permits redistribution and the required notices are included.
