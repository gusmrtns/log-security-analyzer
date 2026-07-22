"""
core/models.py

Estruturas de dados centrais do Log Security Analyzer.

Todo parser converte logs brutos em uma lista de LogEvent (formato normalizado).
Todo detector recebe uma lista de LogEvent e devolve uma lista de Finding.

Manter essas duas classes estáveis é o que permite adicionar novos parsers ou
detectores sem acoplamento entre eles (padrão ETL: Extract -> Transform -> Load).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    """Tipos de evento normalizados, independentes da origem do log."""
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    USER_CREATED = "user_created"
    HTTP_REQUEST = "http_request"
    HTTP_ERROR = "http_error"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severidade de um achado (Finding). Usado para ordenar e colorir relatórios."""
    ALTA = "Alta"
    MEDIA = "Média"
    BAIXA = "Baixa"


@dataclass
class LogEvent:
    """
    Representação normalizada de uma única linha/evento de log,
    independente de o log original ser SSH, Apache ou Windows Event Log.

    Atributos:
        timestamp: Momento do evento. None se o parser não conseguir extrair.
        source_ip: IP de origem, quando aplicável (ex: tentativa de login, request HTTP).
        username: Usuário envolvido no evento, quando aplicável.
        event_type: Categoria normalizada do evento (ver EventType).
        raw_line: Linha original do log, preservada para evidência/auditoria.
        source_file: Nome do arquivo de onde o evento veio.
        extra: Campos adicionais específicos do formato de origem
               (ex: status_code para Apache, event_id para Windows).
    """
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    username: Optional[str]
    event_type: EventType
    raw_line: str
    source_file: str
    extra: dict = field(default_factory=dict)


@dataclass
class Finding:
    """
    Achado gerado por um detector após analisar uma lista de LogEvent.

    Atributos:
        severity: Nível de severidade do achado.
        category: Categoria curta do achado (ex: "brute_force", "off_hours_access").
        title: Título curto e direto do achado.
        description: Explicação detalhada do que foi encontrado e por quê.
        evidence: Lista de LogEvent que sustentam o achado.
        mitre_technique: Técnica MITRE ATT&CK associada, se aplicável (ex: "T1110").
        detector_name: Nome do detector que gerou o achado (preenchido pelo engine).
    """
    severity: Severity
    category: str
    title: str
    description: str
    evidence: list = field(default_factory=list)
    mitre_technique: Optional[str] = None
    detector_name: Optional[str] = None

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)
