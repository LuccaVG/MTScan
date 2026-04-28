# Contributing

## English

MTScan is currently owned and maintained by Lucca Vieira Gentilezza, the sole
copyright holder for the original MTScan project files in this repository.

Contributions are welcome when they improve defensive security testing,
documentation, reliability, reporting, or local app safety.

## Contribution Rules

- Use MTScan only for authorized testing.
- Do not include private scan data, credentials, tokens, customer data, or
  third-party target data in issues, pull requests, tests, or screenshots.
- Keep changes focused and explain the security impact when relevant.
- Add or update tests when changing scanner command construction, reports,
  storage, API responses, or path handling.
- Keep English documentation first and Portuguese (Brazil) second.
- Do not add third-party code, templates, binaries, logos, or assets unless their
  license allows redistribution and the notice is documented.

## Licensing of Contributions

Unless a separate written agreement says otherwise, contributions submitted to
this repository are offered under the same project multi-license grant:

```text
Apache-2.0 OR MIT OR BSD-3-Clause
```

Third-party tools and dependencies are not relicensed by this project. Lucca
Vieira Gentilezza does not claim licensing ownership over `naabu`, `httpx`,
`nuclei`, their templates, binaries, dependencies, names, logos, or trademarks.

## Development Checks

Compile Python files:

```bash
python3 -m py_compile mtscan.py install/setup.py src/workflow.py src/tool_runner.py src/app_server.py src/scan_storage.py
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

Dry-run the complete chain:

```bash
python3 src/workflow.py --dry-run --all -host example.com --save-output --json-output --skip-network-check
```

## Portugues do Brasil

O MTScan atualmente pertence e e mantido por Lucca Vieira Gentilezza, o unico
titular de copyright dos arquivos originais do projeto MTScan neste repositorio.

Contribuicoes sao bem-vindas quando melhoram testes defensivos de seguranca,
documentacao, confiabilidade, relatorios ou seguranca da aplicacao local.

## Regras de Contribuicao

- Use o MTScan somente para testes autorizados.
- Nao inclua dados privados de varredura, credenciais, tokens, dados de clientes
  ou dados de alvos de terceiros em issues, pull requests, testes ou capturas de
  tela.
- Mantenha mudancas focadas e explique o impacto de seguranca quando relevante.
- Adicione ou atualize testes ao mudar construcao de comandos, relatorios,
  armazenamento, respostas da API ou tratamento de caminhos.
- Mantenha documentacao em ingles primeiro e portugues do Brasil em segundo.
- Nao adicione codigo, templates, binarios, logos ou assets de terceiros sem
  permissao de redistribuicao e aviso documentado.

## Licenciamento de Contribuicoes

A menos que exista um acordo escrito separado, contribuicoes enviadas a este
repositorio sao oferecidas sob a mesma concessao multi-licenca do projeto:

```text
Apache-2.0 OR MIT OR BSD-3-Clause
```

Ferramentas e dependencias de terceiros nao sao relicenciadas por este projeto.
Lucca Vieira Gentilezza nao reivindica propriedade de licenca sobre `naabu`,
`httpx`, `nuclei`, seus templates, binarios, dependencias, nomes, logos ou
marcas.
