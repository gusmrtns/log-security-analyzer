"""
core/base.py

Interfaces abstratas para parsers e detectores.

Qualquer novo formato de log (ex: nginx, firewall) só precisa herdar de BaseParser.
Qualquer novo tipo de detecção só precisa herdar de BaseDetector.
O engine.py não conhece as implementações concretas, apenas essas interfaces.
"""

from abc import ABC, abstractmethod
from core.models import LogEvent, Finding


class BaseParser(ABC):
    """Interface para parsers de log. Cada parser sabe ler UM formato específico."""

    name: str = "base_parser"

    @abstractmethod
    def can_parse(self, file_path: str, sample_lines: list) -> bool:
        """
        Heurística rápida para decidir se este parser sabe ler o arquivo.
        Usado quando o formato não é especificado explicitamente via CLI.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, file_path: str) -> list:
        """Lê o arquivo e retorna uma lista de LogEvent normalizados."""
        raise NotImplementedError


class BaseDetector(ABC):
    """Interface para detectores. Cada detector implementa UMA regra de análise."""

    name: str = "base_detector"

    @abstractmethod
    def analyze(self, events: list) -> list:
        """Recebe uma lista de LogEvent e retorna uma lista de Finding."""
        raise NotImplementedError
