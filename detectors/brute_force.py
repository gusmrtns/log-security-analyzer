"""
detectors/brute_force.py

Detecta possíveis ataques de força bruta: muitas falhas de autenticação
vindas do mesmo IP em uma janela de tempo curta.

Lógica:
    1. Agrupa eventos de AUTH_FAILURE por source_ip.
    2. Ordena por timestamp.
    3. Usa uma janela deslizante: se N falhas ocorrem dentro de WINDOW_MINUTES,
       gera um Finding de severidade Alta.
"""

from collections import defaultdict
from datetime import timedelta

from core.base import BaseDetector
from core.models import Finding, Severity, EventType

# Limiares configuráveis. Documentados aqui para facilitar ajuste/calibração
# (mesmo princípio de tuning de regras usado no Wazuh no Projeto 1).
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 5


class BruteForceDetector(BaseDetector):
    name = "brute_force"

    def analyze(self, events: list) -> list:
        findings = []

        failures_by_ip = defaultdict(list)
        for event in events:
            if event.event_type == EventType.AUTH_FAILURE and event.source_ip:
                failures_by_ip[event.source_ip].append(event)

        for ip, ip_events in failures_by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp or 0)
            window_start_idx = 0

            for i in range(len(ip_events)):
                # Avança a borda esquerda da janela até caber em WINDOW_MINUTES
                while (
                    ip_events[i].timestamp
                    and ip_events[window_start_idx].timestamp
                    and ip_events[i].timestamp - ip_events[window_start_idx].timestamp
                    > timedelta(minutes=WINDOW_MINUTES)
                ):
                    window_start_idx += 1

                window_size = i - window_start_idx + 1
                if window_size >= FAILURE_THRESHOLD:
                    evidence = ip_events[window_start_idx: i + 1]
                    targeted_users = sorted({e.username for e in evidence if e.username})

                    findings.append(
                        Finding(
                            severity=Severity.ALTA,
                            category="brute_force",
                            title=f"Possível força bruta a partir de {ip}",
                            description=(
                                f"{window_size} tentativas de autenticação falhas do IP {ip} "
                                f"em uma janela de {WINDOW_MINUTES} minutos. "
                                f"Usuários alvo: {', '.join(targeted_users) if targeted_users else 'não identificado'}."
                            ),
                            evidence=evidence,
                            mitre_technique="T1110",
                            detector_name=self.name,
                        )
                    )
                    # Evita gerar um Finding duplicado para cada evento subsequente
                    # dentro da mesma janela já reportada.
                    window_start_idx = i + 1

        return findings
