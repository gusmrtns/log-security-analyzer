"""
parsers/windows_parser.py

Parser para Windows Event Log exportado em CSV
(ex: via `Get-WinEvent | Export-Csv` ou exportação manual do Event Viewer).

Colunas esperadas no CSV (case-insensitive):
    TimeCreated, Id, LevelDisplayName, Message

Eventos de interesse (Security log):
    4625 -> Falha de logon         -> AUTH_FAILURE
    4624 -> Logon bem-sucedido     -> AUTH_SUCCESS
    4720 -> Conta de usuário criada -> USER_CREATED
"""

import csv
import re
from datetime import datetime

from core.base import BaseParser
from core.models import LogEvent, EventType

EVENT_ID_MAP = {
    "4625": EventType.AUTH_FAILURE,
    "4624": EventType.AUTH_SUCCESS,
    "4720": EventType.USER_CREATED,
}

IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
USER_PATTERN = re.compile(r"Account Name:\s*(\S+)")

TIMESTAMP_FORMATS = ["%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"]


class WindowsParser(BaseParser):
    name = "windows_event_csv"

    def can_parse(self, file_path: str, sample_lines: list) -> bool:
        header = sample_lines[0].lower() if sample_lines else ""
        return "id" in header and ("timecreated" in header or "message" in header)

    def parse(self, file_path: str) -> list:
        events = []
        with open(file_path, "r", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = self._parse_row(row, file_path)
                if event:
                    events.append(event)
        return events

    def _parse_row(self, row: dict, file_path: str):
        # Normaliza nomes de coluna para lidar com variações de export (Id / EventId, etc.)
        normalized = {k.strip().lower(): v for k, v in row.items() if k}

        event_id = normalized.get("id") or normalized.get("eventid")
        if event_id is None:
            return None
        event_id = str(event_id).strip()

        event_type = EVENT_ID_MAP.get(event_id, EventType.UNKNOWN)
        message = normalized.get("message", "")

        ip_match = IP_PATTERN.search(message)
        user_match = USER_PATTERN.search(message)

        timestamp = self._parse_timestamp(normalized.get("timecreated", ""))

        return LogEvent(
            timestamp=timestamp,
            source_ip=ip_match.group(1) if ip_match else None,
            username=user_match.group(1) if user_match else None,
            event_type=event_type,
            raw_line=message or str(row),
            source_file=file_path,
            extra={"event_id": event_id},
        )

    @staticmethod
    def _parse_timestamp(raw: str):
        raw = raw.strip()
        for fmt in TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
        return None
