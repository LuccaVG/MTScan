# Configuration Reference

MTScan configuration currently comes from CLI flags, web scan profiles, environment variables, and installer-generated files.

## Storage environment variables

| Variable | Default | Description |
|---|---|---|
| `MTSCAN_STORAGE_BACKEND` | `auto` | `auto`, `cassandra`, `file`, or `off` |
| `MTSCAN_HISTORY_FILE` | `data/scan_history.jsonl` | Local scan-history JSONL path |
| `MTSCAN_SCHEDULE_FILE` | `data/schedules.json` | Local schedule storage path |
| `MTSCAN_AUTH_FILE` | `data/auth.json` | Local authentication record path |
| `MTSCAN_CASSANDRA_HOSTS` | `127.0.0.1` | Comma-separated Cassandra hosts |
| `MTSCAN_CASSANDRA_PORT` | `9042` | Cassandra native transport port |
| `MTSCAN_CASSANDRA_KEYSPACE` | `mtscan` | Cassandra keyspace; letters/numbers/underscore, starting with a letter |
| `MTSCAN_CASSANDRA_CONNECT_TIMEOUT` | `2` | Cassandra connection timeout in seconds |
| `MTSCAN_CASSANDRA_CONTROL_TIMEOUT` | `2` | Cassandra control connection timeout in seconds |
| `MTSCAN_CASSANDRA_IMPORT_FILE_HISTORY` | `1` | Import existing file history into Cassandra when enabled |
| `MTSCAN_CASSANDRA_IMPORT_LIMIT` | `5000` | Maximum local history records imported during Cassandra initialization |

`auto` tries Cassandra and falls back to the local file store if Cassandra is unavailable.

## Web server options

```bash
python src/app_server.py [--host HOST] [--port PORT] [--allow-remote] [--skip-tool-check] [--no-browser]
```

| Option | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8765` | Listen port |
| `--allow-remote` | off | Required for non-loopback binding |
| `--skip-tool-check` | off | Skip startup scanner status probes |
| `--no-browser` | off | Do not attempt to open the dashboard |

## Built-in web scan profiles

The web app supports `default`, `fast`, `stealth`, and `deep` profiles. Profiles supply scanner options before per-scan overrides are applied.

| Profile | Discovery | Nuclei severity | Nuclei rate | Interactsh |
|---|---|---|---:|---|
| `default` | top 1000 ports | critical, high, medium | 75 | disabled |
| `fast` | top 100 ports | critical, high | 100 | disabled |
| `stealth` | top 1000, connect scan, low rate | critical, high, medium | 5 | disabled |
| `deep` | all ports | critical, high, medium, low | 50 | disabled |

The profile implementation is an alpha interface and may change before stable `1.0.0`.

## Installer-generated configuration

`install/setup.py` may generate `config/optimized_config.json` and shell alias helpers. These files describe installer-selected defaults and paths; the canonical CLI interface remains `src/workflow.py` and its flags.

## Authentication storage

The first-run username is `admin`. The first-run password is generated randomly at runtime and only printed to the local startup console when a new auth record must be initialized. Passwords are stored as derived hashes, not plaintext defaults.

Treat the selected storage backend as sensitive because it also contains scan history, schedules, and/or authentication state.
