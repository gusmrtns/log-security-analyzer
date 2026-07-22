"""
parsers/apache_parser.py

Parser para logs de acesso do Apache/Nginx no formato Common Log Format (CLF)
ou Combined Log Format.

Exemplo de linha reconhecida:
    203.0.113.5 - - [20/Jul/2026:14:32:01 +0000] "GET /admin HTTP/1.1" 404 512
"""

import re
from datetime import datetime

from core.base import BaseParser
from core.models import LogEvent, EventType

CLF_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ApacheParser(BaseParser):
    name = "apache_access_log"

    def can_parse(self, file_path: str, sample_lines: list) -> bool:
        return any(CLF_PATTERN.match(line) for line in sample_lines)

    def parse(self, file_path: str) -> list:
        events = []
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = CLF_PATTERN.match(line)
                if not match:
                    continue

                timestamp = self._parse_timestamp(match["timestamp"])
                status = int(match["status"])
                event_type = EventType.HTTP_ERROR if status >= 400 else EventType.HTTP_REQUEST
                user = match["user"] if match["user"] != "-" else None

                events.append(LogEvent(
                    timestamp=timestamp,
                    source_ip=match["ip"],
                    username=user,
                    event_type=event_type,
                    raw_line=line,
                    source_file=file_path,
                    extra={"method": match["method"], "path": match["path"], "status": status},
                ))
        return events

    @staticmethod
    def _parse_timestamp(raw: str):
        try:
            return datetime.strptime(raw, TIMESTAMP_FORMAT)
        except ValueError:
            return None
