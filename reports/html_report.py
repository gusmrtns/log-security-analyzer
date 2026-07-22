"""
reports/html_report.py

Gera um relatório HTML autocontido (CSS embutido, sem dependências externas
no navegador) a partir dos achados encontrados.
"""

from datetime import datetime
from collections import Counter

from jinja2 import Template

from core.models import Severity

SEVERITY_COLOR = {
    Severity.ALTA: "#dc2626",
    Severity.MEDIA: "#d97706",
    Severity.BAIXA: "#0891b2",
}

TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Log Security Analyzer — Relatório</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }
  .container { max-width: 900px; margin: 0 auto; }
  h1 { color: #f8fafc; border-bottom: 2px solid #334155; padding-bottom: 12px; }
  .meta { color: #94a3b8; font-size: 14px; margin-bottom: 24px; }
  .summary { display: flex; gap: 16px; margin-bottom: 32px; }
  .summary-card { background: #1e293b; border-radius: 8px; padding: 16px 24px; flex: 1; text-align: center; }
  .summary-card .count { font-size: 28px; font-weight: bold; }
  .summary-card .label { font-size: 13px; color: #94a3b8; }
  .finding { background: #1e293b; border-left: 4px solid; border-radius: 6px; padding: 16px 20px; margin-bottom: 14px; }
  .finding-title { font-weight: bold; font-size: 15px; margin-bottom: 6px; }
  .badge { display: inline-block; font-size: 12px; padding: 2px 8px; border-radius: 999px; color: white; margin-right: 8px; }
  .finding-desc { color: #cbd5e1; font-size: 14px; line-height: 1.5; }
  .finding-meta { color: #64748b; font-size: 12px; margin-top: 8px; }
  .no-findings { background: #14532d; color: #bbf7d0; padding: 16px; border-radius: 8px; }
</style>
</head>
<body>
<div class="container">
  <h1>Log Security Analyzer</h1>
  <div class="meta">
    Gerado em {{ generated_at }} &nbsp;|&nbsp;
    Arquivos: {{ files_analyzed | join(', ') }} &nbsp;|&nbsp;
    Eventos processados: {{ total_events }}
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="count">{{ findings | length }}</div>
      <div class="label">Total de achados</div>
    </div>
    {% for sev, count in severity_counts %}
    <div class="summary-card">
      <div class="count" style="color: {{ severity_colors[sev] }}">{{ count }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  {% if findings %}
    {% for f in findings %}
    <div class="finding" style="border-left-color: {{ severity_colors[f.severity] }};">
      <div class="finding-title">
        <span class="badge" style="background: {{ severity_colors[f.severity] }};">{{ f.severity.value }}</span>
        {{ f.title }}
      </div>
      <div class="finding-desc">{{ f.description }}</div>
      <div class="finding-meta">
        {% if f.mitre_technique %}MITRE ATT&CK: {{ f.mitre_technique }} &nbsp;|&nbsp;{% endif %}
        Evidências: {{ f.evidence_count }} evento(s) &nbsp;|&nbsp; Detector: {{ f.detector_name }}
      </div>
    </div>
    {% endfor %}
  {% else %}
    <div class="no-findings">Nenhum padrão suspeito identificado.</div>
  {% endif %}
</div>
</body>
</html>
"""


def write_report(findings: list, total_events: int, files_analyzed: list, output_path: str):
    counts = Counter(f.severity.value for f in findings)
    severity_counts = [(s.value, counts[s.value]) for s in [Severity.ALTA, Severity.MEDIA, Severity.BAIXA] if counts[s.value]]
    severity_colors = {s.value: c for s, c in SEVERITY_COLOR.items()}

    html = Template(TEMPLATE).render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        files_analyzed=files_analyzed,
        total_events=total_events,
        findings=findings,
        severity_counts=severity_counts,
        severity_colors=severity_colors,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
