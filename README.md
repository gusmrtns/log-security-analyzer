# Log Security Analyzer

Ferramenta CLI em Python para análise automatizada de logs de segurança. Identifica padrões suspeitos — força bruta, enumeração de usuários, acessos fora de horário, varredura de endpoints sensíveis e criação de contas suspeitas — em logs de SSH, Apache e Windows Event Log, gerando relatórios em terminal, JSON e HTML.

Projeto desenvolvido como parte da minha trilha de portfólio em Segurança Defensiva (Blue Team), na sequência do [Wazuh SIEM Home Lab](https://github.com/gusmrtns/wazuh-home-lab).

## Por que este projeto

A maioria das detecções em um SOC começa com análise de log — SIEMs como o Wazuh automatizam boa parte disso, mas entender a lógica por trás da detecção (parsing, normalização, correlação por janela de tempo) é uma habilidade fundamental e independente de ferramenta. Este projeto implementa esse pipeline do zero, em Python puro, sem depender de nenhuma plataforma de SIEM.

## Arquitetura

O projeto segue um pipeline em camadas inspirado no padrão ETL (Extract, Transform, Load), separando claramente parsing, normalização, detecção e geração de relatório:

```
arquivo de log bruto
        ↓
  Parser específico do formato (SSH / Apache / Windows)
        ↓
  LogEvent — estrutura normalizada, comum a todos os formatos
        ↓
  Detectores (brute force, anomalia, reputação de IP, scan de endpoints, criação de conta)
        ↓
  Finding — achado com severidade, evidência e técnica MITRE associada
        ↓
  Relatório (terminal / JSON / HTML)
```

Essa separação permite adicionar um novo formato de log ou uma nova regra de detecção sem alterar o restante do sistema — parsers e detectores dependem apenas das interfaces `BaseParser` e `BaseDetector` (`core/base.py`), nunca um do outro diretamente.

```
log-security-analyzer/
├── analyzer.py                  # CLI entrypoint
├── core/
│   ├── models.py                 # LogEvent, Finding, enums
│   ├── base.py                   # Interfaces BaseParser / BaseDetector
│   └── engine.py                 # Orquestra parsers + detectores
├── parsers/
│   ├── ssh_parser.py              # auth.log (SSH/syslog)
│   ├── apache_parser.py           # access.log (Common/Combined Log Format)
│   └── windows_parser.py          # Windows Event Log exportado em CSV
├── detectors/
│   ├── brute_force.py             # Falhas de login em janela deslizante
│   ├── anomaly.py                 # Login fora de horário comercial
│   ├── ip_reputation.py           # Enumeração de usuários + top IPs por volume
│   ├── endpoint_scan.py           # Varredura de endpoints sensíveis (admin, .env, etc.)
│   └── account_creation.py        # Criação de conta suspeita (nome/IP externo)
├── reports/
│   ├── terminal_report.py         # Saída colorida (rich)
│   ├── json_report.py             # Exportação estruturada
│   └── html_report.py             # Relatório HTML autocontido
├── sample-logs/
│   └── generate_sample_logs.py    # Gerador de logs sintéticos para teste
└── tests/
    └── test_detectors.py          # Testes unitários (pytest)
```

## Detecções implementadas

| Detecção | Técnica MITRE ATT&CK | Severidade | Lógica |
|---|---|---|---|
| Força bruta | T1110 | Alta | ≥5 falhas de login do mesmo IP em janela de 5 minutos |
| Enumeração de usuários | T1087 | Alta | Mesmo IP tentando ≥4 usernames distintos |
| Varredura de endpoints sensíveis | T1595.002 | Alta | Mesmo IP batendo em ≥3 caminhos sensíveis conhecidos (`/admin`, `/.env`, etc.) |
| Varredura genérica (volume) | T1595 | Média | ≥10 erros HTTP do mesmo IP em janela de 5 minutos |
| Criação de conta suspeita | T1136.001 | Alta | Nome de usuário suspeito e/ou origem de IP externo (fora de RFC1918) |
| Criação de conta padrão | T1136.001 | Média | Conta criada a partir de IP interno, sem padrão suspeito no nome |
| Login fora de horário | — | Média | Login bem-sucedido fora de 7h–20h |
| Top IPs por volume | — | Baixa | IPs com maior volume de eventos (contexto, não é detecção isolada) |

## Formatos de log suportados

- **SSH / auth.log** — formato syslog padrão (`Failed password`, `Accepted password`, `Invalid user`)
- **Apache / Nginx access.log** — Common Log Format e Combined Log Format
- **Windows Event Log** — exportado em CSV (colunas `TimeCreated`, `Id`, `Message`), eventos 4624 (logon), 4625 (falha de logon), 4720 (conta criada)

O formato é detectado automaticamente por heurística nas primeiras linhas do arquivo, ou pode ser forçado com `--format`.

## Instalação

```bash
git clone https://github.com/gusmrtns/log-security-analyzer.git
cd log-security-analyzer
pip install -r requirements.txt
```

## Uso

Gerar logs sintéticos para testar (sem depender de nenhuma VM):

```bash
python sample-logs/generate_sample_logs.py
```

Rodar a análise:

```bash
python analyzer.py sample-logs/auth.log
```

Exportar relatório em JSON e HTML:

```bash
python analyzer.py sample-logs/auth.log --json reports/out.json --html reports/out.html
```

Analisar múltiplos arquivos de uma vez:

```bash
python analyzer.py sample-logs/auth.log sample-logs/access.log
```

Forçar um formato específico (quando a heurística de detecção não é suficiente):

```bash
python analyzer.py meu_log.txt --format apache_access_log
```

O comando retorna código de saída `1` quando há achados de severidade Alta — pensado para uso em pipelines de CI/automação.

## Testes

```bash
pytest -v
```

17 testes cobrindo os cinco detectores (casos positivos e negativos) e o parser de SSH.

## Validação com dados sintéticos

Os logs em `sample-logs/` são gerados sinteticamente (`generate_sample_logs.py`, com seed fixa para reprodutibilidade) e incluem, deliberadamente:

- Tráfego normal em SSH, HTTP e Windows (para validar ausência de falsos positivos)
- Um cenário de força bruta SSH (8 falhas do mesmo IP contra o usuário `root`)
- Um cenário de enumeração de usuários SSH (mesmo IP testando 6 usernames diferentes)
- Um login SSH legítimo fora de horário comercial
- Uma varredura de endpoints sensíveis via HTTP (`/admin`, `/wp-login.php`, `/.env`, `/config.php`, `/phpmyadmin`, `/.git/config`)
- Uma criação de conta administrativa suspeita no Windows Event Log (`backdoor_adm`, a partir de IP externo)

Rodando o analyzer contra `auth.log`, `access.log` e `windows_events.csv`, a ferramenta identifica corretamente os 5 padrões maliciosos plantados nos três formatos, sem falsos positivos no tráfego normal — mesma taxa de detecção (100%) do Projeto 1 (Wazuh Home Lab), agora em uma ferramenta construída do zero.

> Uma validação adicional com logs reais, coletados de uma VM dedicada, será documentada em uma atualização futura deste repositório.

## Próximos passos

- Suporte a mais formatos de log (nginx, firewall)
- Detecção de impossible travel (login do mesmo usuário em geolocalizações incompatíveis)
- Empacotamento como pacote instalável (`pip install .`)

## Stack

Python 3.10+, `re`, `argparse`, `dataclasses`, `rich`, `Jinja2`, `pytest`, GitHub Actions (CI).

## Projetos relacionados

- [Wazuh SIEM Home Lab](https://github.com/gusmrtns/wazuh-home-lab) — ambiente de SIEM completo com detecção de 5 técnicas MITRE ATT&CK

## Autor

Francisco Gustavo Martins de Sousa — Estudante de Ciência da Computação (UFC), foco em Segurança Defensiva.
[LinkedIn](https://linkedin.com/in/gus-martins) · [GitHub](https://github.com/gusmrtns)
