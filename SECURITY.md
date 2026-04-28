# Security Policy

## English

MTScan is a security testing tool. It must be used only on systems you own or
are explicitly authorized to assess.

## Supported Scope

Security issues in this repository include:

- API leaks from the local web app
- Unsafe file path handling
- Incorrect command redaction
- Unsafe handling of scan output
- Installation behavior that exposes secrets or writes outside expected paths
- Documentation that could lead users to unsafe operation

Scanner findings discovered by `naabu`, `httpx`, or `nuclei` against a third
party target are not vulnerabilities in MTScan itself.

## Reporting a Vulnerability

If you find a security issue in MTScan:

1. Do not publish exploit details before the maintainer has had time to review.
2. Include a clear description, affected files or endpoints, reproduction steps,
   and impact.
3. Include whether secrets, paths, scan output, or system data could leak.
4. Avoid sending real credentials, private scan data, or third-party target data.

If this project is hosted on GitHub, use the repository security advisory flow
when available. Otherwise, contact the maintainer privately before opening a
public issue with sensitive details.

## Local App Hardening

The local web app is designed to reduce accidental exposure:

- Loopback bind by default
- `--allow-remote` required for non-loopback bind
- Host header allowlist
- Security headers on JSON and static responses
- Request size limit
- Static path traversal protection
- API redaction for local paths and sensitive command values

Remote binding should be used only inside a trusted lab network or behind a
properly authenticated reverse proxy.

## Responsible Use

MTScan can run active network scanners. Unauthorized scanning can be illegal,
harmful, or disruptive. Always obtain permission, define scan scope, and respect
rate limits.

## Português do Brasil

MTScan é uma ferramenta de testes de segurança. Ela deve ser usada somente em
sistemas que você possui ou tem autorização explícita para avaliar.

## Escopo Suportado

Problemas de segurança neste repositório incluem:

- Vazamentos na API da aplicação web local
- Tratamento inseguro de caminhos de arquivo
- Redação incorreta de comandos
- Tratamento inseguro da saída dos scanners
- Instalação que exponha segredos ou escreva fora dos caminhos esperados
- Documentação que possa induzir uso inseguro

Achados que `naabu`, `httpx` ou `nuclei` encontram em um alvo de terceiro não
são vulnerabilidades do próprio MTScan.

## Como Reportar

Se você encontrar uma falha de segurança no MTScan:

1. Não publique detalhes de exploração antes da revisão do mantenedor.
2. Inclua descrição clara, arquivos ou endpoints afetados, passos de reprodução
   e impacto.
3. Informe se segredos, caminhos, saída de scan ou dados do sistema podem vazar.
4. Evite enviar credenciais reais, dados privados de varredura ou dados de
   alvos de terceiros.

Se o projeto estiver no GitHub, use o fluxo de security advisory quando
disponível. Caso contrário, fale com o mantenedor de forma privada antes de
abrir uma issue pública com detalhes sensíveis.

## Uso Responsável

O MTScan pode executar scanners ativos de rede. Varredura sem autorização pode
ser ilegal, prejudicial ou disruptiva. Sempre obtenha permissão, defina o escopo
e respeite limites de taxa.
