"""
detectors/anomaly.py

Detecta acessos bem-sucedidos (login) fora do horário comercial configurado.
Um login fora de horário não é necessariamente malicioso, mas é um indicador
que vale investigação — por isso a severidade padrão é Média, não Alta.
"""

from core.base import BaseDetector
from core.models import Finding, Severity, EventType

# Horário comercial considerado "normal". Ajustável conforme o contexto do ambiente.
BUSINESS_HOUR_START = 7
BUSINESS_HOUR_END = 20


class AnomalyDetector(BaseDetector):
    name = "off_hours_access"

    def analyze(self, events: list) -> list:
        findings = []

        off_hours_events = [
            e for e in events
            if e.event_type == EventType.AUTH_SUCCESS
            and e.timestamp
            and not (BUSINESS_HOUR_START <= e.timestamp.hour < BUSINESS_HOUR_END)
        ]

        # Agrupa por usuário para não gerar um Finding por evento individual.
        by_user = {}
        for event in off_hours_events:
            by_user.setdefault(event.username or "desconhecido", []).append(event)

        for user, user_events in by_user.items():
            findings.append(
                Finding(
                    severity=Severity.MEDIA,
                    category="off_hours_access",
                    title=f"Login fora do horário comercial: usuário '{user}'",
                    description=(
                        f"{len(user_events)} login(s) bem-sucedido(s) do usuário '{user}' "
                        f"fora da janela de horário comercial ({BUSINESS_HOUR_START}h–{BUSINESS_HOUR_END}h). "
                        "Verificar se corresponde a atividade legítima (plantão, fuso diferente, etc.)."
                    ),
                    evidence=user_events,
                    detector_name=self.name,
                )
            )

        return findings
