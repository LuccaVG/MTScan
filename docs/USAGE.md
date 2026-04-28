# MTScan Usage Guide

## English

MTScan has three user-facing paths:

- Option `[1]` in `mtscan.py`: complete CLI chain
- Option `[2]` in `mtscan.py`: single-tool CLI scan
- Option `[3]` in `mtscan.py`: local web app

The same scanner runner powers the menu, direct CLI, and app, so output and
reporting stay consistent.

## Target Rules

Accepted target styles:

```text
example.com
sub.example.com
https://example.com
192.168.1.10
127.0.0.1
```

Use only targets you own or have explicit written permission to assess.

## Complete CLI Chain

Run `naabu`, then `httpx`, then `nuclei`:

```bash
python3 src/workflow.py --all -host example.com --top-ports 100 --save-output --json-output
```

The chain works like this:

1. `naabu` discovers open ports.
2. `httpx` checks discovered services for HTTP or HTTPS.
3. `nuclei` scans discovered HTTP URLs.
4. MTScan writes one report: `vulnerability_report.md`.

If no intermediate targets are discovered, MTScan falls back to the original
target where that makes sense.

## Single-Tool CLI Scans

Port discovery:

```bash
python3 src/workflow.py -naabu -host example.com --top-ports 100 --save-output
```

HTTP service analysis:

```bash
python3 src/workflow.py -httpx -host example.com --title --status-code --tech-detect --save-output --json-output
```

Nuclei vulnerability assessment:

```bash
python3 src/workflow.py -nuclei -host https://example.com --severity critical,high --save-output --json-output
```

Dry run:

```bash
python3 src/workflow.py --dry-run --all -host example.com --save-output --json-output
```

## Interactive Menu

Start:

```bash
python3 mtscan.py
```

Main choices:

- `[1] Complete CLI Scan Chain`: runs `naabu -> httpx -> nuclei`
- `[2] Single Tool CLI Scan`: opens a submenu for `naabu`, `httpx`, or `nuclei`
- `[3] Launch Local Web App`: starts the dashboard on localhost
- `[4] View Previous Results`: opens saved `results_*` folders
- `[5] Update Nuclei Templates`: runs nuclei template update
- `[7] Install/Update Tools`: updates scanner binaries or reruns setup tasks
- `[8] Help & Documentation`: prints a local quick reference

## Local Web App

Start:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

The app supports:

- Chain and single-tool scans
- Dry-run previews
- Live output
- Public scan summaries
- Historical graph data
- Storage status in health output

The app is local-first and redacts local paths and sensitive command values from
API responses.

Remote binding is blocked unless explicitly enabled:

```bash
python3 src/app_server.py --host 0.0.0.0 --port 8765 --allow-remote
```

Only use remote binding behind controls you trust, such as a private lab network
or a reverse proxy with authentication.

## Report

Saved scans create a `results_*` directory. The main human report is:

```text
vulnerability_report.md
```

Read it from top to bottom:

1. Executive summary
2. Severity counts
3. Priority findings
4. Remediation plan
5. Detailed findings
6. Exposure context
7. Tool execution notes

The report focuses on fix guidance. Raw scanner files remain in the result
folder for evidence and deeper investigation.

## Storage for Graphs

The web app stores completed scan summaries, not raw scanner output, for graph
history.

Default mode:

```bash
export MTSCAN_STORAGE_BACKEND=auto
```

Use Cassandra when available:

```bash
docker compose -f docker-compose.cassandra.yml up -d
python3 src/app_server.py
```

Use file storage:

```bash
export MTSCAN_STORAGE_BACKEND=file
export MTSCAN_HISTORY_FILE=data/scan_history.jsonl
```

Disable storage:

```bash
export MTSCAN_STORAGE_BACKEND=off
```

## Validation Commands

Compile Python files:

```bash
python3 -m py_compile mtscan.py install/setup.py src/workflow.py src/tool_runner.py src/app_server.py src/scan_storage.py
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

Check scanner availability:

```bash
python3 src/workflow.py --check-tools
```

## Português do Brasil

O MTScan tem três caminhos principais de uso:

- Opção `[1]` no `mtscan.py`: cadeia CLI completa
- Opção `[2]` no `mtscan.py`: varredura CLI com uma única ferramenta
- Opção `[3]` no `mtscan.py`: aplicação web local

O menu, o CLI direto e a aplicação usam o mesmo runner, mantendo saída e
relatórios consistentes.

## Regras de Alvo

Formatos aceitos:

```text
example.com
sub.example.com
https://example.com
192.168.1.10
127.0.0.1
```

Use apenas alvos que você possui ou tem permissão explícita por escrito para
avaliar.

## Cadeia CLI Completa

Executa `naabu`, depois `httpx`, depois `nuclei`:

```bash
python3 src/workflow.py --all -host example.com --top-ports 100 --save-output --json-output
```

Fluxo da cadeia:

1. `naabu` descobre portas abertas.
2. `httpx` verifica serviços HTTP ou HTTPS.
3. `nuclei` analisa URLs HTTP descobertas.
4. MTScan escreve um único relatório: `vulnerability_report.md`.

## Varreduras com Uma Ferramenta

Descoberta de portas:

```bash
python3 src/workflow.py -naabu -host example.com --top-ports 100 --save-output
```

Análise HTTP:

```bash
python3 src/workflow.py -httpx -host example.com --title --status-code --tech-detect --save-output --json-output
```

Avaliação com nuclei:

```bash
python3 src/workflow.py -nuclei -host https://example.com --severity critical,high --save-output --json-output
```

Dry run:

```bash
python3 src/workflow.py --dry-run --all -host example.com --save-output --json-output
```

## Menu Interativo

Iniciar:

```bash
python3 mtscan.py
```

Opções principais:

- `[1] Complete CLI Scan Chain`: executa `naabu -> httpx -> nuclei`
- `[2] Single Tool CLI Scan`: abre submenu para `naabu`, `httpx` ou `nuclei`
- `[3] Launch Local Web App`: inicia o painel em localhost
- `[4] View Previous Results`: abre pastas `results_*`
- `[5] Update Nuclei Templates`: atualiza templates do nuclei
- `[7] Install/Update Tools`: atualiza binários ou tarefas de setup
- `[8] Help & Documentation`: mostra referência local

## Aplicação Web Local

Iniciar:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Abrir:

```text
http://127.0.0.1:8765
```

A aplicação oferece varreduras completas ou por ferramenta, dry-run, saída ao
vivo, histórico, gráficos e status de armazenamento.

Bind remoto só é permitido de forma explícita:

```bash
python3 src/app_server.py --host 0.0.0.0 --port 8765 --allow-remote
```

Use bind remoto apenas atrás de controles confiáveis, como rede de laboratório
privada ou proxy reverso com autenticação.

## Relatório

Varreduras salvas criam uma pasta `results_*`. O relatório principal é:

```text
vulnerability_report.md
```

Ele deve ser lido nesta ordem: resumo executivo, severidades, achados
prioritários, plano de correção, detalhes, contexto de exposição e notas das
ferramentas.

## Armazenamento para Gráficos

A aplicação web armazena resumos de varreduras concluídas, não a saída bruta
dos scanners, para alimentar os gráficos.

Modo padrão:

```bash
export MTSCAN_STORAGE_BACKEND=auto
```

Cassandra:

```bash
docker compose -f docker-compose.cassandra.yml up -d
python3 src/app_server.py
```

Arquivo local:

```bash
export MTSCAN_STORAGE_BACKEND=file
export MTSCAN_HISTORY_FILE=data/scan_history.jsonl
```

Desativar armazenamento:

```bash
export MTSCAN_STORAGE_BACKEND=off
```
