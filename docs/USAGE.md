# MTScan Usage Guide

## English

MTScan is now used through the authenticated local web app. Option `[1]` in
`mtscan.py` starts the console for manual scans, recurring schedules, monitoring,
findings, assets, and reports.

The same scanner runner powers the web app, so scan output and reporting stay
consistent while the user-facing scan workflow stays in the browser.

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

## Web Console Scans

Launch the local app:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`, sign in with `admin` / `admin`, and change the
password when prompted.

The chain mode works like this:

1. `naabu` discovers open ports.
2. `httpx` checks discovered services for HTTP or HTTPS.
3. `nuclei` scans discovered HTTP URLs.
4. MTScan writes one report: `vulnerability_report.md`.

If no intermediate targets are discovered, MTScan falls back to the original
target where that makes sense.

## Interactive Menu

Start:

```bash
python3 mtscan.py
```

Main choices:

- `[1] Launch Local Web App`: starts the dashboard on localhost with persisted history
- `[2] View Previous Results`: opens saved `results_*` folders
- `[3] Update Nuclei Templates`: runs nuclei template update
- `[4] Tool Configuration`: points configuration work to the web console
- `[5] Install/Update Tools`: updates scanner binaries or reruns setup tasks
- `[6] Help & Documentation`: prints a local quick reference

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
- Recurring scan schedules
- Dashboard, findings, assets, reports, and settings views
- Dry-run previews
- Live output
- Sanitized scan summaries
- Historical graph data
- Storage status in health output

The default login is `admin` / `admin`. The app requires a password change
after the first successful login.

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
sudo systemctl enable --now cassandra
python3 src/app_server.py
```

From the interactive menu, option `[1] Launch Local Web App` checks the native
Cassandra service and uses it when `cassandra-driver` can connect.

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

Safe local severity validation:

```bash
python3 tests/fixtures/local_vuln_server.py --host 127.0.0.1 --port 8899
```

In another terminal:

```bash
python3 src/workflow.py --all -host 127.0.0.1 --ports 8899 --save-output --json-output --skip-network-check --template-path tests/fixtures/nuclei-local-severity --no-interactsh
```

This fixture binds only to loopback and serves static markers, not a real
vulnerable application. Expected report counts are 4 security findings
(`critical`, `high`, `medium`, `low`) and 1 informational observation.

## Português do Brasil

O MTScan agora é usado pela aplicação web local autenticada. A opção `[1]` no
`mtscan.py` inicia o console para varreduras manuais, agendamentos, monitoramento,
achados, ativos e relatórios.

A aplicação usa o mesmo runner interno, mantendo saída e relatórios
consistentes enquanto o fluxo de varredura fica no navegador.

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

## Varreduras Pelo Console Web

Inicie a aplicação local:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Acesse `http://127.0.0.1:8765`, entre com `admin` / `admin` e troque a senha
quando solicitado.

Fluxo da cadeia:

1. `naabu` descobre portas abertas.
2. `httpx` verifica serviços HTTP ou HTTPS.
3. `nuclei` analisa URLs HTTP descobertas.
4. MTScan escreve um único relatório: `vulnerability_report.md`.

## Menu Interativo

Iniciar:

```bash
python3 mtscan.py
```

Opções principais:

- `[1] Launch Local Web App`: inicia o painel em localhost com histórico persistente
- `[2] View Previous Results`: abre pastas `results_*`
- `[3] Update Nuclei Templates`: atualiza templates do nuclei
- `[4] Tool Configuration`: aponta configuração para o console web
- `[5] Install/Update Tools`: atualiza binários ou tarefas de setup
- `[6] Help & Documentation`: mostra referência local

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
sudo systemctl enable --now cassandra
python3 src/app_server.py
```

No menu interativo, a opção `[1] Launch Local Web App` verifica o serviço
nativo do Cassandra e o usa quando `cassandra-driver` consegue conectar.

Arquivo local:

```bash
export MTSCAN_STORAGE_BACKEND=file
export MTSCAN_HISTORY_FILE=data/scan_history.jsonl
```

Desativar armazenamento:

```bash
export MTSCAN_STORAGE_BACKEND=off
```
