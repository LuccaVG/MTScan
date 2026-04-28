# Code Scanning

## English

MTScan uses a layered GitHub security pipeline in
`.github/workflows/code-scanning.yml`.

The workflow runs:

- CodeQL for Python and JavaScript security analysis
- Semgrep with default, security-audit, and secrets rules, uploaded as SARIF
- `pip-audit` for vulnerable Python dependencies in `config/requirements.txt`
- Bandit for Python security patterns
- Dependency Review on pull requests

CodeQL and Semgrep upload findings to GitHub code scanning. Bandit and
`pip-audit` upload JSON reports as workflow artifacts. Dependency Review and
`pip-audit` catch dependency risk that source-code scanners may not see.

No automated scanner can find every possible vulnerability. This pipeline is
intended to give broad coverage and early warning, not to replace manual review,
threat modeling, or testing on Linux.

## GitHub Requirements

Code scanning works on public GitHub repositories. Private or internal
repositories may require GitHub Code Security or GitHub Advanced Security to be
enabled.

Required workflow permissions are declared in the workflow:

- `security-events: write` for CodeQL and SARIF upload jobs
- `contents: read` for checkout
- `actions: read` where GitHub requires it for code scanning uploads

## How To Use

The workflow runs on:

- Pushes to any branch
- Pull requests
- Weekly scheduled scans
- Manual `workflow_dispatch`

After pushing to GitHub, open the repository Security tab and check:

- Code scanning alerts
- Dependabot alerts
- Dependency review results on pull requests

## Portugues do Brasil

O MTScan usa uma pipeline de seguranca em camadas no GitHub em
`.github/workflows/code-scanning.yml`.

O workflow executa:

- CodeQL para analise de seguranca em Python e JavaScript
- Semgrep com regras default, security-audit e secrets, enviado como SARIF
- `pip-audit` para dependencias Python vulneraveis em `config/requirements.txt`
- Bandit para padroes de seguranca em Python
- Dependency Review em pull requests

CodeQL e Semgrep enviam achados para o code scanning do GitHub. Bandit e
`pip-audit` enviam relatorios JSON como artefatos do workflow. Dependency Review
e `pip-audit` cobrem risco de dependencias que scanners de codigo podem nao
enxergar.

Nenhum scanner automatico encontra todas as vulnerabilidades possiveis. Esta
pipeline serve para ampliar cobertura e dar alerta cedo, nao para substituir
revisao manual, modelagem de ameacas ou testes no Linux.

## Requisitos no GitHub

Code scanning funciona em repositorios publicos no GitHub. Repositorios privados
ou internos podem exigir GitHub Code Security ou GitHub Advanced Security.

As permissoes necessarias estao declaradas no workflow:

- `security-events: write` para CodeQL e uploads SARIF
- `contents: read` para checkout
- `actions: read` onde o GitHub exige para uploads de code scanning

## Como Usar

O workflow roda em:

- Pushes para qualquer branch
- Pull requests
- Varreduras semanais agendadas
- Execucao manual via `workflow_dispatch`

Depois de enviar ao GitHub, abra a aba Security do repositorio e verifique:

- Code scanning alerts
- Dependabot alerts
- Resultados do Dependency Review em pull requests
