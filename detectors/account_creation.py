"""
detectors/account_creation.py

Detecta criação de contas de usuário, escalando a severidade conforme o
contexto:
    - Alta: conta criada a partir de um IP de origem externo (fora das
      faixas privadas RFC1918), ou com nome de usuário em padrão suspeito
      (ex: "backdoor", "temp", "svc_" seguido de números aleatórios).
    - Média: conta criada a partir de um IP interno, sem padrão suspeito
      no nome (ainda vale revisão, mas é o caso comum de administração
      legítima).

Mesma técnica MITRE do Projeto 1 (Wazuh Home Lab): T1136.001 - Create
Account: Local Account.
"""

import ipaddress
import re

from core.base import BaseDetector
from core.models import Finding, Severity, EventType

SUSPICIOUS_USERNAME_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"backdoor", r"^temp", r"^test", r"hack", r"^svc_?\d+$", r"^adm(in)?\d+$",
    ]
]


# Apenas as faixas RFC 1918 (rede interna real). Deliberadamente NÃO usamos
# ipaddress.is_private, pois esse atributo também marca como "privadas" faixas
# reservadas para documentação (ex: 203.0.113.0/24, usada nos nossos próprios
# logs sintéticos como IP "atacante"), loopback e link-local - o que mascararia
# IPs claramente externos como se fossem internos.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


class AccountCreationDetector(BaseDetector):
    name = "account_creation"

    def analyze(self, events: list) -> list:
        findings = []

        for event in events:
            if event.event_type != EventType.USER_CREATED:
                continue

            username = event.username or "desconhecido"
            suspicious_name = any(pat.search(username) for pat in SUSPICIOUS_USERNAME_PATTERNS)
            external_ip = bool(event.source_ip) and not _is_private_ip(event.source_ip)

            if suspicious_name or external_ip:
                severity = Severity.ALTA
                reasons = []
                if suspicious_name:
                    reasons.append("nome de usuário segue padrão suspeito")
                if external_ip:
                    reasons.append(f"origem é um IP externo ({event.source_ip})")
                reason_text = " e ".join(reasons)
            else:
                severity = Severity.MEDIA
                reason_text = "criação de conta padrão a partir de origem interna, requer revisão de rotina"

            findings.append(
                Finding(
                    severity=severity,
                    category="account_creation",
                    title=f"Conta de usuário criada: '{username}'",
                    description=(
                        f"Nova conta '{username}' criada"
                        f"{f' a partir do IP {event.source_ip}' if event.source_ip else ''}. "
                        f"Motivo da classificação: {reason_text}."
                    ),
                    evidence=[event],
                    mitre_technique="T1136.001",
                    detector_name=self.name,
                )
            )

        return findings
