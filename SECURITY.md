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

## Portugues do Brasil

MTScan e uma ferramenta de testes de seguranca. Ela deve ser usada somente em
sistemas que voce possui ou tem autorizacao explicita para avaliar.

## Escopo Suportado

Problemas de seguranca neste repositorio incluem:

- Vazamentos na API da aplicacao web local
- Tratamento inseguro de caminhos de arquivo
- Redacao incorreta de comandos
- Tratamento inseguro da saida dos scanners
- Instalacao que exponha segredos ou escreva fora dos caminhos esperados
- Documentacao que possa induzir uso inseguro

Achados que `naabu`, `httpx` ou `nuclei` encontram em um alvo de terceiro nao
sao vulnerabilidades do proprio MTScan.

## Como Reportar

Se voce encontrar uma falha de seguranca no MTScan:

1. Nao publique detalhes de exploracao antes da revisao do mantenedor.
2. Inclua descricao clara, arquivos ou endpoints afetados, passos de reproducao
   e impacto.
3. Informe se segredos, caminhos, saida de scan ou dados do sistema podem vazar.
4. Evite enviar credenciais reais, dados privados de varredura ou dados de
   alvos de terceiros.

Se o projeto estiver no GitHub, use o fluxo de security advisory quando
disponivel. Caso contrario, fale com o mantenedor de forma privada antes de
abrir uma issue publica com detalhes sensiveis.

## Uso Responsavel

O MTScan pode executar scanners ativos de rede. Varredura sem autorizacao pode
ser ilegal, prejudicial ou disruptiva. Sempre obtenha permissao, defina o escopo
e respeite limites de taxa.
