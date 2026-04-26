# Code Citations - MTScan

MTScan is a Python wrapper around three external ProjectDiscovery tools:

- Naabu: https://github.com/projectdiscovery/naabu
- HTTPX: https://github.com/projectdiscovery/httpx
- Nuclei: https://github.com/projectdiscovery/nuclei

The MTScan code uses Python standard library modules for process execution,
filesystem access, networking checks, argument parsing, and report file writing.

Python dependencies are declared in `config/requirements.txt`.

Current project scope:

- Interactive menu in `mtscan.py`
- CLI workflow in `src/workflow.py`
- Shared tool execution in `src/tool_runner.py`
- Thin wrapper modules in `commands/`
- Linux installer in `install/setup.py`

Removed scope:

- No web app or desktop app exists yet.
- No source-code scanner is part of the runtime scope.
- No missing `run.py`, `scripts/`, or test launcher is documented as supported.
