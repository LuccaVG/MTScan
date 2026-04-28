# MTScan

MTScan is a Linux-focused vulnerability analysis toolkit that orchestrates the
ProjectDiscovery scanners `naabu`, `httpx`, and `nuclei`.

It is designed to be usable in three ways:

- Complete CLI chain: `naabu -> httpx -> nuclei`
- Single-tool CLI scans: choose only `naabu`, `httpx`, or `nuclei`
- Local web app: a localhost dashboard with live output, scan history, and graph data

Use MTScan only on systems you own or have explicit permission to test.

## What It Produces

MTScan now writes one high-level report per saved scan:

```text
vulnerability_report.md
```

The report is meant to show, explain, and help fix vulnerabilities. It combines:

- Executive summary
- Severity counts
- Priority findings
- Remediation plan
- Finding details
- Exposure context
- Tool execution notes

Run with `--json-output` when possible so the report can include richer nuclei
metadata such as descriptions, references, and remediation text.

## Requirements

- Native Linux VM or host
- Python 3.8+
- Internet access for installation, template updates, and public target scans
- Go, when installing ProjectDiscovery tools from source
- `naabu`, `httpx`, and `nuclei`

## Install

From the project root:

```bash
sudo python3 install/setup.py
```

The installer exposes Go-installed scanner binaries through `/usr/local/bin`
when it has sudo privileges. If your shell cannot find the tools after install:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

Detailed setup notes are in [docs/INSTALL.md](docs/INSTALL.md).

## CLI Usage

Complete chain:

```bash
python3 src/workflow.py --all -host example.com --top-ports 100 --save-output --json-output
```

Single tool:

```bash
python3 src/workflow.py -naabu -host example.com --top-ports 100
python3 src/workflow.py -httpx -host example.com --title --status-code --tech-detect
python3 src/workflow.py -nuclei -host https://example.com --severity critical,high --json-output
```

Dry run without launching scanners:

```bash
python3 src/workflow.py --dry-run --all -host example.com --save-output --json-output
```

Check scanner availability:

```bash
python3 src/workflow.py --check-tools
```

## Interactive Menu

Start the menu:

```bash
python3 mtscan.py
```

Current menu flow:

- `[1]` Complete CLI Scan Chain
- `[2]` Single Tool CLI Scan
- `[3]` Launch Local Web App
- `[4]` View Previous Results
- `[5]` Update Nuclei Templates
- `[6]` Tool Configuration
- `[7]` Install/Update Tools
- `[8]` Help & Documentation

Usage details are in [docs/USAGE.md](docs/USAGE.md).

## Local Web App

Start the app on loopback:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

The app uses the shared Python scanner runner. It includes live logs, scan
history, result summaries, and graphs for findings and exposed surface.

The app is intentionally local-first:

- Binds to `127.0.0.1` by default
- Refuses non-loopback binds unless `--allow-remote` is passed
- Restricts Host headers
- Sends defensive browser headers
- Redacts local paths and sensitive command values in API payloads
- Limits request size and retained in-memory logs

## Local History Storage

The web app stores completed scan summaries for graph history. It tries
Cassandra first and falls back to a local JSONL file if Cassandra is not
available.

Optional local Cassandra:

```bash
docker compose -f docker-compose.cassandra.yml up -d
python3 src/app_server.py
```

Storage environment variables:

- `MTSCAN_STORAGE_BACKEND=auto|cassandra|file|off`
- `MTSCAN_HISTORY_FILE=data/scan_history.jsonl`
- `MTSCAN_CASSANDRA_HOSTS=127.0.0.1`
- `MTSCAN_CASSANDRA_PORT=9042`
- `MTSCAN_CASSANDRA_KEYSPACE=mtscan`
- `MTSCAN_CASSANDRA_CONNECT_TIMEOUT=2`
- `MTSCAN_CASSANDRA_CONTROL_TIMEOUT=2`

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): installation and setup
- [docs/USAGE.md](docs/USAGE.md): CLI, menu, web app, reports
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution rules and license terms
- [SECURITY.md](SECURITY.md): security policy and responsible use
- [docs/CODE_SCANNING.md](docs/CODE_SCANNING.md): GitHub code scanning pipeline
- [docs/LICENSING.md](docs/LICENSING.md): project license and third-party notes
- [licenses/](licenses/): full license texts and third-party notices

## License

MTScan is owned by Lucca Vieira Gentilezza and is open source under a
multi-license grant: Apache-2.0 OR MIT OR BSD-3-Clause. See [LICENSE](LICENSE),
[NOTICE](NOTICE), [licenses/](licenses/), and [docs/LICENSING.md](docs/LICENSING.md).

Copyright 2026 Lucca Vieira Gentilezza.

Third-party tools keep their own upstream licenses. Lucca Vieira Gentilezza does
not claim licensing ownership or relicensing rights over the tools used by this
project, including `naabu`, `httpx`, `nuclei`, their templates, binaries,
dependencies, names, logos, or trademarks.

## Português do Brasil

MTScan é um kit de análise de vulnerabilidades focado em Linux que orquestra os
scanners ProjectDiscovery `naabu`, `httpx` e `nuclei`.

Ele pode ser usado de três formas:

- Cadeia completa no CLI: `naabu -> httpx -> nuclei`
- Varredura CLI com uma única ferramenta: `naabu`, `httpx` ou `nuclei`
- Aplicação web local: painel em localhost com saída ao vivo, histórico e gráficos

Use o MTScan somente em sistemas que você possui ou tem permissão explícita
para testar.

## Relatório Principal

Cada varredura salva gera um único relatório humano:

```text
vulnerability_report.md
```

Esse relatório mostra, explica e ajuda a corrigir vulnerabilidades. Ele inclui
resumo executivo, severidades, achados prioritários, plano de correção, detalhes
dos achados, contexto de exposição e notas de execução das ferramentas.

Use `--json-output` sempre que possível para enriquecer o relatório com
descrições, referências e remediações vindas do nuclei.

## Instalação

Na raiz do projeto:

```bash
sudo python3 install/setup.py
```

Se o shell não encontrar as ferramentas depois da instalação:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

Mais detalhes estão em [docs/INSTALL.md](docs/INSTALL.md).

## Uso Rápido

Cadeia completa:

```bash
python3 src/workflow.py --all -host example.com --top-ports 100 --save-output --json-output
```

Uma ferramenta:

```bash
python3 src/workflow.py -naabu -host example.com --top-ports 100
python3 src/workflow.py -httpx -host example.com --title --status-code --tech-detect
python3 src/workflow.py -nuclei -host https://example.com --severity critical,high --json-output
```

Aplicação local:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Abra `http://127.0.0.1:8765`.

## Armazenamento Local

A aplicação web guarda resumos de varreduras concluídas para alimentar os
gráficos. Ela tenta usar Cassandra primeiro e volta para `data/scan_history.jsonl`
se o Cassandra não estiver disponível.

Subir Cassandra local:

```bash
docker compose -f docker-compose.cassandra.yml up -d
python3 src/app_server.py
```

## Licença

MTScan pertence a Lucca Vieira Gentilezza e é open source sob uma concessão
multi-licença: Apache-2.0 OR MIT OR BSD-3-Clause. Veja [LICENSE](LICENSE),
[NOTICE](NOTICE), [licenses/](licenses/) e [docs/LICENSING.md](docs/LICENSING.md).

Copyright 2026 Lucca Vieira Gentilezza.

As ferramentas de terceiros mantêm suas próprias licenças upstream. Lucca Vieira
Gentilezza não reivindica propriedade de licença ou direito de relicenciar as
ferramentas usadas por este projeto, incluindo `naabu`, `httpx`, `nuclei`, seus
templates, binários, dependências, nomes, logos ou marcas.
