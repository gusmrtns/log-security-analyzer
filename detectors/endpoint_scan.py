"""
detectors/endpoint_scan.py

Detecta varredura de endpoints sensíveis: um mesmo IP gerando muitos erros
HTTP (4xx) em um curto intervalo, especialmente contra caminhos comumente
alvo de reconhecimento automatizado (painéis de admin, arquivos de config,
credenciais expostas, etc.).

Dois sinais, cada um suficiente por si só para gerar um Finding:
    1. IP bate em N ou mais caminhos da lista de padrões sensíveis conhecidos.
    2. IP gera um volume alto de respostas 4xx em uma janela curta de tempo
       (varredura genérica, mesmo contra caminhos não listados).
"""

import re
from collections import defaultdict
from datetime import timedelta

from core.base import BaseDetector
from core.models import Finding, Severity, EventType

SENSITIVE_PATH_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"^/admin", r"wp-login\.php", r"\.env$", r"config\.php",
        r"phpmyadmin", r"\.git/config", r"\.aws/credentials", r"\.ssh/",
    ]
]

SENSITIVE_HIT_THRESHOLD = 3     # nº de caminhos sensíveis distintos batidos pelo mesmo IP
GENERIC_ERROR_THRESHOLD = 10    # nº de erros 4xx do mesmo IP na janela, independente do caminho
WINDOW_MINUTES = 5


class EndpointScanDetector(BaseDetector):
    name = "endpoint_scan"

    def analyze(self, events: list) -> list:
        findings = []

        errors_by_ip = defaultdict(list)
        for event in events:
            if event.event_type == EventType.HTTP_ERROR and event.source_ip:
                errors_by_ip[event.source_ip].append(event)

        for ip, ip_events in errors_by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp or 0)

            sensitive_hits = [
                e for e in ip_events
                if any(pat.search(e.extra.get("path", "")) for pat in SENSITIVE_PATH_PATTERNS)
            ]
            if len(sensitive_hits) >= SENSITIVE_HIT_THRESHOLD:
                hit_paths = sorted({e.extra.get("path", "") for e in sensitive_hits})
                findings.append(
                    Finding(
                        severity=Severity.ALTA,
                        category="endpoint_scan",
                        title=f"Varredura de endpoints sensíveis a partir de {ip}",
                        description=(
                            f"O IP {ip} gerou {len(sensitive_hits)} erro(s) HTTP contra "
                            f"caminho(s) sensíveis conhecidos: {', '.join(hit_paths)}. "
                            "Padrão típico de reconhecimento automatizado (scanner)."
                        ),
                        evidence=sensitive_hits,
                        mitre_technique="T1595.002",
                        detector_name=self.name,
                    )
                )
                continue  # já reportado por padrão sensível; evita duplicar com o sinal genérico

            findings.extend(self._detect_generic_burst(ip, ip_events))

        return findings

    def _detect_generic_burst(self, ip: str, ip_events: list) -> list:
        window_start_idx = 0
        findings = []

        for i in range(len(ip_events)):
            while (
                ip_events[i].timestamp
                and ip_events[window_start_idx].timestamp
                and ip_events[i].timestamp - ip_events[window_start_idx].timestamp
                > timedelta(minutes=WINDOW_MINUTES)
            ):
                window_start_idx += 1

            window_size = i - window_start_idx + 1
            if window_size >= GENERIC_ERROR_THRESHOLD:
                evidence = ip_events[window_start_idx: i + 1]
                findings.append(
                    Finding(
                        severity=Severity.MEDIA,
                        category="endpoint_scan",
                        title=f"Alto volume de erros HTTP a partir de {ip}",
                        description=(
                            f"{window_size} respostas de erro HTTP do IP {ip} em uma janela de "
                            f"{WINDOW_MINUTES} minutos. Possível varredura genérica."
                        ),
                        evidence=evidence,
                        mitre_technique="T1595",
                        detector_name=self.name,
                    )
                )
                window_start_idx = i + 1

        return findings
