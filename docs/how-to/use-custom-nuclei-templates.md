# Use Custom Nuclei Templates

## Goal

Run a reviewed local Nuclei template through MTScan.

## Run one template

```bash
python3 src/workflow.py \
  --nuclei \
  -host https://target.example \
  --templates ./templates/custom-check.yaml \
  --json-output \
  --save-output
```

`--template-path` is also accepted and maps to the Nuclei template selection when `--templates` is not supplied.

## Filter by tags

```bash
python3 src/workflow.py \
  --nuclei \
  -host https://target.example \
  --tags cve,misconfig \
  --severity critical,high \
  --json-output \
  --save-output
```

## Security review checklist

Before running a custom template:

1. Confirm its source and integrity.
2. Read the requests, matchers, extractors, workflows, and any JavaScript/code sections.
3. Check whether it uses Interactsh or other external callbacks.
4. Confirm it stays inside the authorized target scope.
5. Use an isolated lab for templates that may alter state or invoke code.

MTScan does not sandbox Nuclei templates. Nuclei executes the template according to its own capabilities and configuration.

## Disable Interactsh

```bash
python3 src/workflow.py \
  --nuclei \
  -host https://target.example \
  --templates ./templates/custom-check.yaml \
  --no-interactsh \
  --save-output
```

The web app's built-in profiles disable Interactsh by default.
