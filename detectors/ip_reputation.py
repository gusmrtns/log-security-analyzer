"""
detectors/ip_reputation.py

Dois sinais relacionados a comportamento suspeito de IP de origem:

1. Enumeração de usuários: um mesmo IP tentando autenticar com muitos
   usernames diferentes (típico de ataque de enumeração/spray).
2. Top IPs por volume de eventos: não é uma detecção de ataque por si só,
   mas útil como contexto no relatório (severidade Baixa).

Este detector não consulta listas de reputação externas (a ferramenta é
offline por design); o nome reflete o objetivo do gap analysis original
(ver README) mas a implementação foca em heurísticas locais.
"""

from collections import defaultdict, Counter

from core.base import BaseDetector
from core.models import Finding, Severity, EventType

DISTINCT_USER_THRESHOLD = 4
TOP_IPS_TO_REPORT = 10
MIN_EVENTS_FOR_TOP_IP_FINDING = 20


class IPReputationDetector(BaseDetector):
    name = "ip_reputation"

    def analyze(self, events: list) -> list:
        findings = []
        findings.extend(self._detect_user_enumeration(events))
        findings.extend(self._detect_top_ips(events))
        return findings

    def _detect_user_enumeration(self, events: list) -> list:
        users_by_ip = defaultdict(set)
        evidence_by_ip = defaultdict(list)

        for event in events:
            if event.event_type == EventType.AUTH_FAILURE and event.source_ip and event.username:
                users_by_ip[event.source_ip].add(event.username)
                evidence_by_ip[event.source_ip].append(event)

        findings = []
        for ip, users in users_by_ip.items():
            if len(users) >= DISTINCT_USER_THRESHOLD:
                findings.append(
                    Finding(
                        severity=Severity.ALTA,
                        category="user_enumeration",
                        title=f"Possível enumeração de usuários a partir de {ip}",
                        description=(
                            f"O IP {ip} tentou autenticação com {len(users)} usuários distintos "
                            f"({', '.join(sorted(users))}). Padrão típico de enumeração ou password spray."
                        ),
                        evidence=evidence_by_ip[ip],
                        mitre_technique="T1087",
                        detector_name=self.name,
                    )
                )
        return findings

    def _detect_top_ips(self, events: list) -> list:
        ip_counter = Counter(e.source_ip for e in events if e.source_ip)
        if not ip_counter:
            return []

        top_ips = ip_counter.most_common(TOP_IPS_TO_REPORT)
        busiest_ip, busiest_count = top_ips[0]

        if busiest_count < MIN_EVENTS_FOR_TOP_IP_FINDING:
            return []

        summary = ", ".join(f"{ip} ({count})" for ip, count in top_ips)
        evidence = [e for e in events if e.source_ip == busiest_ip][:20]

        return [
            Finding(
                severity=Severity.BAIXA,
                category="top_ips_by_volume",
                title=f"IP com maior volume de eventos: {busiest_ip} ({busiest_count} eventos)",
                description=f"Top {len(top_ips)} IPs por volume de eventos: {summary}.",
                evidence=evidence,
                detector_name=self.name,
            )
        ]
