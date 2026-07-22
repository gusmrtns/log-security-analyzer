"""
core/engine.py

Orquestra o pipeline: seleciona o parser certo para cada arquivo,
extrai os LogEvent, roda todos os detectores e devolve os Finding.

O engine não conhece detalhes de nenhum parser ou detector específico —
ele só depende das interfaces BaseParser e BaseDetector.
"""

from parsers.ssh_parser import SSHParser
from parsers.apache_parser import ApacheParser
from parsers.windows_parser import WindowsParser

from detectors.brute_force import BruteForceDetector
from detectors.anomaly import AnomalyDetector
from detectors.ip_reputation import IPReputationDetector
from detectors.endpoint_scan import EndpointScanDetector
from detectors.account_creation import AccountCreationDetector

# Registro central de parsers e detectores disponíveis.
# Adicionar um novo formato ou regra = adicionar uma linha aqui.
AVAILABLE_PARSERS = [SSHParser(), ApacheParser(), WindowsParser()]
AVAILABLE_DETECTORS = [
    BruteForceDetector(),
    AnomalyDetector(),
    IPReputationDetector(),
    EndpointScanDetector(),
    AccountCreationDetector(),
]


def select_parser(file_path: str, forced_format: str = None):
    """Escolhe o parser adequado, por formato forçado (--format) ou por heurística."""
    if forced_format:
        for parser in AVAILABLE_PARSERS:
            if parser.name == forced_format:
                return parser
        raise ValueError(f"Formato '{forced_format}' não reconhecido.")

    with open(file_path, "r", errors="ignore") as f:
        sample_lines = [next(f, "") for _ in range(20)]

    for parser in AVAILABLE_PARSERS:
        if parser.can_parse(file_path, sample_lines):
            return parser

    return None


def run_pipeline(file_paths: list, forced_format: str = None):
    """
    Executa o pipeline completo para uma lista de arquivos de log.

    Retorna:
        (all_events, all_findings, unparsed_files)
    """
    all_events = []
    unparsed_files = []

    for file_path in file_paths:
        parser = select_parser(file_path, forced_format)
        if parser is None:
            unparsed_files.append(file_path)
            continue
        all_events.extend(parser.parse(file_path))

    all_findings = []
    for detector in AVAILABLE_DETECTORS:
        all_findings.extend(detector.analyze(all_events))

    return all_events, all_findings, unparsed_files
