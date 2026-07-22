"""
parsers/ssh_parser.py

Parser para logs de autenticação SSH no formato do /var/log/auth.log (Linux/Debian/Ubuntu).

Exemplos de linhas reconhecidas:
    Jul 20 14:32:01 srv sshd[1234]: Failed password for root from 203.0.113.5 port 51422 ssh2
    Jul 20 14:32:05 srv sshd[1234]: Accepted password for gustavo from 192.168.1.10 port 51423 ssh2
    Jul 20 14:35:10 srv sshd[1234]: Invalid user admin from 203.0.113.5 port 51500
"""

import re
from datetime import datetime

from core.base import BaseParser
from core.models import LogEvent, EventType

# Ano não aparece no auth.log tradicional (formato syslog). Assumimos o ano corrente,
# mas deixamos como constante para facilitar ajuste caso os logs sejam de outro ano.
DEFAULT_YEAR = datetime.now().year

# Regex para a linha padrão de syslog: "Mon DD HH:MM:SS host sshd[pid]: mensagem"
SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


class SSHParser(BaseParser):
    name = "ssh_auth_log"

    def can_parse(self, file_path: str, sample_lines: list) -> bool:
        # Heurística: se pelo menos uma linha bate com o prefixo sshd[pid], é um auth.log.
        return any(SYSLOG_PREFIX.match(line) for line in sample_lines)

    def parse(self, file_path: str) -> list:
        events = []
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line, file_path)
                if event:
                    events.append(event)
        return events

    def _parse_line(self, line: str, file_path: str):
        prefix_match = SYSLOG_PREFIX.match(line)
        if not prefix_match:
            return None

        timestamp = self._build_timestamp(prefix_match["month"], prefix_match["day"], prefix_match["time"])
        message = prefix_match["message"]

        failed = FAILED_PASSWORD.search(message)
        if failed:
            return LogEvent(
                timestamp=timestamp,
                source_ip=failed["ip"],
                username=failed["user"],
                event_type=EventType.AUTH_FAILURE,
                raw_line=line,
                source_file=file_path,
            )

        accepted = ACCEPTED_PASSWORD.search(message)
        if accepted:
            return LogEvent(
                timestamp=timestamp,
                source_ip=accepted["ip"],
                username=accepted["user"],
                event_type=EventType.AUTH_SUCCESS,
                raw_line=line,
                source_file=file_path,
            )

        invalid = INVALID_USER.search(message)
        if invalid:
            return LogEvent(
                timestamp=timestamp,
                source_ip=invalid["ip"],
                username=invalid["user"],
                event_type=EventType.AUTH_FAILURE,
                raw_line=line,
                source_file=file_path,
                extra={"reason": "invalid_user"},
            )

        # Linha reconhecida como sshd, mas sem padrão de interesse mapeado.
        return LogEvent(
            timestamp=timestamp,
            source_ip=None,
            username=None,
            event_type=EventType.UNKNOWN,
            raw_line=line,
            source_file=file_path,
        )

    @staticmethod
    def _build_timestamp(month_str: str, day_str: str, time_str: str):
        try:
            dt_str = f"{DEFAULT_YEAR} {month_str} {int(day_str):02d} {time_str}"
            return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
