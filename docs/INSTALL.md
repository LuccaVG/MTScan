# MTScan Installation Guide

## English

MTScan is built for native Linux. Windows and macOS can be used for reading,
editing, dry runs, and UI work, but real scanner execution should happen on a
Linux host or VM.

## Supported Environment

- Debian, Ubuntu, Kali, Arch, or a similar native Linux distribution
- Python 3.8 or newer
- `pip3`
- Go, when installing ProjectDiscovery scanners from source
- Internet access for package installation, scanner installation, nuclei
  template updates, and public target scans

## Full Install

Run from the repository root:

```bash
sudo python3 install/setup.py
```

The installer:

- Checks Linux system requirements
- Installs required OS packages where possible
- Installs Python dependencies from `config/requirements.txt`
- Installs or updates `naabu`, `httpx`, and `nuclei`
- Exposes scanner binaries through `/usr/local/bin` when sudo is available
- Updates nuclei templates when nuclei is installed

If a scanner is installed but not found by your shell:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

## Python Dependencies Only

For development or dry-run work:

```bash
python3 -m pip install -r config/requirements.txt
```

The Cassandra driver is included as an optional dependency for durable graph
history. If Cassandra is unavailable, the app falls back to a local JSONL file.

## Scanner Checks

After installation:

```bash
python3 src/workflow.py --check-tools
```

Expected scanners:

- `naabu`
- `httpx`
- `nuclei`

## Optional Local Cassandra

Start Cassandra for persistent web app graph history:

```bash
docker compose -f docker-compose.cassandra.yml up -d
```

Then start the app:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Storage settings:

```bash
export MTSCAN_STORAGE_BACKEND=auto
export MTSCAN_CASSANDRA_HOSTS=127.0.0.1
export MTSCAN_CASSANDRA_PORT=9042
export MTSCAN_CASSANDRA_KEYSPACE=mtscan
```

Use file-only storage:

```bash
export MTSCAN_STORAGE_BACKEND=file
export MTSCAN_HISTORY_FILE=data/scan_history.jsonl
```

Disable history storage:

```bash
export MTSCAN_STORAGE_BACKEND=off
```

## Linux Smoke Test

This validates argument handling and report path creation without launching
network scanners:

```bash
python3 src/workflow.py --dry-run --all -host example.com --top-ports 100 --save-output --json-output --skip-network-check
```

For real scans, remove `--dry-run` and use only authorized targets.

## Troubleshooting

If tools are missing:

```bash
which naabu
which httpx
which nuclei
echo "$PATH"
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

If nuclei templates are stale:

```bash
python3 src/workflow.py -nuclei -host https://example.com --update-templates --dry-run
nuclei -update-templates
```

If installation fails because of disk space, clear package caches and retry:

```bash
sudo apt clean
sudo apt autoremove
sudo python3 install/setup.py
```

## Português do Brasil

O MTScan foi feito para Linux nativo. Windows e macOS podem ser usados para ler,
editar, rodar dry-run e trabalhar na interface, mas a execução real dos scanners
deve acontecer em um host ou VM Linux.

## Ambiente Suportado

- Debian, Ubuntu, Kali, Arch ou uma distribuição Linux parecida
- Python 3.8 ou mais novo
- `pip3`
- Go, quando a instalação das ferramentas ProjectDiscovery for feita por código fonte
- Internet para pacotes, ferramentas, templates do nuclei e varreduras em alvos públicos

## Instalação Completa

Na raiz do repositório:

```bash
sudo python3 install/setup.py
```

O instalador:

- Verifica requisitos do Linux
- Instala pacotes do sistema quando possível
- Instala dependências Python de `config/requirements.txt`
- Instala ou atualiza `naabu`, `httpx` e `nuclei`
- Expõe binários em `/usr/local/bin` quando há sudo
- Atualiza templates do nuclei quando o nuclei está instalado

Se uma ferramenta estiver instalada mas não for encontrada:

```bash
export PATH="$PATH:/usr/local/bin:$HOME/go/bin"
```

## Apenas Dependências Python

Para desenvolvimento ou dry-run:

```bash
python3 -m pip install -r config/requirements.txt
```

O driver Cassandra é opcional para histórico persistente de gráficos. Se o
Cassandra não estiver disponível, a aplicação usa um arquivo JSONL local.

## Verificação dos Scanners

Depois da instalação:

```bash
python3 src/workflow.py --check-tools
```

Ferramentas esperadas:

- `naabu`
- `httpx`
- `nuclei`

## Cassandra Local Opcional

Suba o Cassandra para histórico persistente dos gráficos:

```bash
docker compose -f docker-compose.cassandra.yml up -d
```

Depois inicie a aplicação:

```bash
python3 src/app_server.py --host 127.0.0.1 --port 8765
```

Configurações de armazenamento:

```bash
export MTSCAN_STORAGE_BACKEND=auto
export MTSCAN_CASSANDRA_HOSTS=127.0.0.1
export MTSCAN_CASSANDRA_PORT=9042
export MTSCAN_CASSANDRA_KEYSPACE=mtscan
```

Usar somente arquivo local:

```bash
export MTSCAN_STORAGE_BACKEND=file
export MTSCAN_HISTORY_FILE=data/scan_history.jsonl
```

Desativar histórico:

```bash
export MTSCAN_STORAGE_BACKEND=off
```

## Teste Rápido no Linux

Este comando valida argumentos e criação de caminhos de relatório sem executar
scanners de rede:

```bash
python3 src/workflow.py --dry-run --all -host example.com --top-ports 100 --save-output --json-output --skip-network-check
```

Para varreduras reais, remova `--dry-run` e use apenas alvos autorizados.
