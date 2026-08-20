# Support

## Start with the documentation

Use the documentation index at [docs/README.md](docs/README.md). Common starting points are:

- [Installation](docs/getting-started/installation.md)
- [Quickstart](docs/getting-started/quickstart.md)
- [Troubleshooting](docs/how-to/troubleshooting.md)
- [CLI reference](docs/reference/cli.md)
- [Limitations](docs/concepts/limitations.md)

## Bug reports and usage questions

Open a GitHub issue for reproducible MTScan bugs or documentation gaps that do not contain sensitive information.

Include:

- MTScan version or commit.
- Linux distribution and version.
- Python version.
- Naabu, HTTPX, and Nuclei versions when relevant.
- The exact MTScan command with secrets removed.
- Expected behavior.
- Actual behavior and exit code.
- Minimal sanitized logs.

Do not attach real credentials, authorization headers, API keys, customer data, private scanner output, or unredacted internal target inventories.

## Security vulnerabilities

Do not use a public support issue for a vulnerability in MTScan. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting when available.

## Upstream scanner support

If the problem reproduces when running `naabu`, `httpx`, or `nuclei` directly and does not depend on MTScan command construction or parsing, report it to the appropriate ProjectDiscovery project. Include an MTScan issue only when MTScan changes the behavior or result.

## Unsupported requests

The project does not provide authorization for scanning third-party systems and cannot verify that a target is legally in scope for you. The operator is responsible for authorization, rules of engagement, and target availability.
