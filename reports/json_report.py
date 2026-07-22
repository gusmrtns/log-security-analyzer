"""
reports/json_report.py

Exporta os achados (Finding) para um arquivo JSON estruturado,
útil para integração com outras ferramentas (SIEM, dashboards, CI).
"""

import json
from datetime import datetime


def _event_to_dict(event) -> dict:
    return {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_ip": event.source_ip,
        "username": event.username,
        "event_type": event.event_type.value,
        "raw_line": event.raw_line,
        "source_file": event.source_file,
    }


def _finding_to_dict(finding) -> dict:
    return {
        "severity": finding.severity.value,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "mitre_technique": finding.mitre_technique,
        "detector_name": finding.detector_name,
        "evidence_count": finding.evidence_count,
        "evidence": [_event_to_dict(e) for e in finding.evidence],
    }


def write_report(findings: list, total_events: int, files_analyzed: list, output_path: str):
    report = {
        "generated_at": datetime.now().isoformat(),
        "files_analyzed": files_analyzed,
        "total_events": total_events,
        "total_findings": len(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path
