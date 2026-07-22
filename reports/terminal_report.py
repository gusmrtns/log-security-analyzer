"""
reports/terminal_report.py

Imprime um relatório colorido no terminal usando a lib `rich`.
"""

from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.models import Severity

SEVERITY_COLOR = {
    Severity.ALTA: "bold red",
    Severity.MEDIA: "bold yellow",
    Severity.BAIXA: "bold cyan",
}

# Ordem de exibição: mais crítico primeiro.
SEVERITY_ORDER = [Severity.ALTA, Severity.MEDIA, Severity.BAIXA]


def print_report(findings: list, total_events: int, files_analyzed: list, console: Console = None):
    console = console or Console()

    console.print()
    console.print(Panel.fit(
        "[bold]Log Security Analyzer[/bold] — Relatório de Análise",
        border_style="bright_blue",
    ))

    console.print(f"Arquivos analisados: {', '.join(files_analyzed)}")
    console.print(f"Eventos processados: {total_events}")
    console.print(f"Achados encontrados: {len(findings)}")
    console.print()

    if not findings:
        console.print("[bold green]Nenhum padrão suspeito identificado.[/bold green]")
        return

    counts = Counter(f.severity for f in findings)
    summary = Table(title="Resumo por Severidade", show_header=True, header_style="bold")
    summary.add_column("Severidade")
    summary.add_column("Quantidade", justify="right")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            summary.add_row(f"[{SEVERITY_COLOR[sev]}]{sev.value}[/{SEVERITY_COLOR[sev]}]", str(counts[sev]))
    console.print(summary)
    console.print()

    ordered_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    for idx, finding in enumerate(ordered_findings, start=1):
        color = SEVERITY_COLOR[finding.severity]
        title = f"[{color}]#{idx} [{finding.severity.value}][/{color}] {finding.title}"

        body = finding.description
        if finding.mitre_technique:
            body += f"\n[dim]MITRE ATT&CK: {finding.mitre_technique}[/dim]"
        body += f"\n[dim]Evidências: {finding.evidence_count} evento(s) | Detector: {finding.detector_name}[/dim]"

        console.print(Panel(body, title=title, border_style=color.split()[-1], title_align="left"))
