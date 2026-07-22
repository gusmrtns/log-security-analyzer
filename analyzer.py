#!/usr/bin/env python3
"""
analyzer.py

CLI do Log Security Analyzer.

Uso básico:
    python analyzer.py sample-logs/auth.log
    python analyzer.py sample-logs/auth.log sample-logs/access.log --format apache_access_log
    python analyzer.py sample-logs/auth.log --json reports/out.json
    python analyzer.py sample-logs/auth.log --html reports/out.html
"""

import argparse
import sys

from rich.console import Console

from core.engine import run_pipeline
from reports.terminal_report import print_report
from reports import json_report, html_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Analisador automatizado de logs de segurança (SSH, Apache, Windows Event Log).",
    )
    parser.add_argument(
        "log_files",
        nargs="+",
        help="Um ou mais arquivos de log a serem analisados.",
    )
    parser.add_argument(
        "--format",
        choices=["ssh_auth_log", "apache_access_log", "windows_event_csv"],
        default=None,
        help="Força um formato específico em vez de detectar automaticamente.",
    )
    parser.add_argument(
        "--json",
        metavar="ARQUIVO",
        default=None,
        help="Exporta o relatório em formato JSON para o caminho informado.",
    )
    parser.add_argument(
        "--html",
        metavar="ARQUIVO",
        default=None,
        help="Exporta o relatório em formato HTML para o caminho informado.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Não imprime o relatório no terminal (útil ao usar apenas --json/--html).",
    )
    return parser


def main():
    args = build_arg_parser().parse_args()
    console = Console()

    events, findings, unparsed = run_pipeline(args.log_files, forced_format=args.format)

    if unparsed:
        for file_path in unparsed:
            console.print(f"[bold yellow]Aviso:[/bold yellow] não foi possível identificar o formato de '{file_path}'. Use --format para especificar manualmente.")

    if not args.quiet:
        print_report(findings, total_events=len(events), files_analyzed=args.log_files, console=console)

    if args.json:
        path = json_report.write_report(findings, len(events), args.log_files, args.json)
        console.print(f"[bold green]Relatório JSON salvo em:[/bold green] {path}")

    if args.html:
        path = html_report.write_report(findings, len(events), args.log_files, args.html)
        console.print(f"[bold green]Relatório HTML salvo em:[/bold green] {path}")

    # Exit code não-zero se houver achados de severidade Alta — útil para CI/automação.
    high_severity_count = sum(1 for f in findings if f.severity.value == "Alta")
    if high_severity_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
