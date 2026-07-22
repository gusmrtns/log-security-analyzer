"""
tests/test_detectors.py

Testes unitários para parsers e detectores.
Rodar com: pytest -v
"""

import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import LogEvent, EventType
from detectors.brute_force import BruteForceDetector
from detectors.anomaly import AnomalyDetector
from detectors.ip_reputation import IPReputationDetector
from detectors.endpoint_scan import EndpointScanDetector
from detectors.account_creation import AccountCreationDetector
from parsers.ssh_parser import SSHParser


def make_event(event_type, ip="203.0.113.5", user="root", minutes_offset=0, base=None, extra=None):
    base = base or datetime(2026, 7, 20, 10, 0, 0)
    return LogEvent(
        timestamp=base + timedelta(minutes=minutes_offset),
        source_ip=ip,
        username=user,
        event_type=event_type,
        raw_line="linha de teste",
        source_file="test.log",
        extra=extra or {},
    )


class TestBruteForceDetector:
    def test_detects_brute_force_within_window(self):
        events = [
            make_event(EventType.AUTH_FAILURE, minutes_offset=i * 0.5)
            for i in range(6)
        ]
        findings = BruteForceDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].category == "brute_force"
        assert findings[0].mitre_technique == "T1110"

    def test_no_finding_below_threshold(self):
        events = [make_event(EventType.AUTH_FAILURE, minutes_offset=i) for i in range(3)]
        findings = BruteForceDetector().analyze(events)
        assert len(findings) == 0

    def test_no_finding_when_spread_outside_window(self):
        # 5 falhas, mas espalhadas em 30 minutos (fora da janela de 5 min).
        events = [make_event(EventType.AUTH_FAILURE, minutes_offset=i * 10) for i in range(5)]
        findings = BruteForceDetector().analyze(events)
        assert len(findings) == 0


class TestAnomalyDetector:
    def test_detects_off_hours_login(self):
        late_night = datetime(2026, 7, 20, 23, 30, 0)
        events = [make_event(EventType.AUTH_SUCCESS, user="carla", base=late_night)]
        findings = AnomalyDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].category == "off_hours_access"

    def test_no_finding_during_business_hours(self):
        business_hours = datetime(2026, 7, 20, 14, 0, 0)
        events = [make_event(EventType.AUTH_SUCCESS, user="carla", base=business_hours)]
        findings = AnomalyDetector().analyze(events)
        assert len(findings) == 0


class TestIPReputationDetector:
    def test_detects_user_enumeration(self):
        events = [
            make_event(EventType.AUTH_FAILURE, user=f"user{i}", minutes_offset=i)
            for i in range(5)
        ]
        findings = IPReputationDetector().analyze(events)
        enum_findings = [f for f in findings if f.category == "user_enumeration"]
        assert len(enum_findings) == 1

    def test_no_enumeration_below_threshold(self):
        events = [
            make_event(EventType.AUTH_FAILURE, user="root", minutes_offset=i)
            for i in range(3)
        ]
        findings = IPReputationDetector().analyze(events)
        enum_findings = [f for f in findings if f.category == "user_enumeration"]
        assert len(enum_findings) == 0


class TestEndpointScanDetector:
    def test_detects_sensitive_path_scan(self):
        paths = ["/admin", "/wp-login.php", "/.env", "/config.php"]
        events = [
            make_event(EventType.HTTP_ERROR, minutes_offset=i, extra={"path": p, "status": 404})
            for i, p in enumerate(paths)
        ]
        findings = EndpointScanDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].category == "endpoint_scan"
        assert findings[0].mitre_technique == "T1595.002"

    def test_detects_generic_error_burst_without_sensitive_paths(self):
        events = [
            make_event(EventType.HTTP_ERROR, minutes_offset=i * 0.2, extra={"path": f"/page{i}", "status": 404})
            for i in range(12)
        ]
        findings = EndpointScanDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].mitre_technique == "T1595"

    def test_no_finding_for_isolated_errors(self):
        events = [
            make_event(EventType.HTTP_ERROR, minutes_offset=i * 30, extra={"path": "/notfound", "status": 404})
            for i in range(2)
        ]
        findings = EndpointScanDetector().analyze(events)
        assert len(findings) == 0


class TestAccountCreationDetector:
    def test_flags_suspicious_username_as_high_severity(self):
        events = [make_event(EventType.USER_CREATED, ip="203.0.113.5", user="backdoor_adm")]
        findings = AccountCreationDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].severity.value == "Alta"
        assert findings[0].mitre_technique == "T1136.001"

    def test_flags_external_ip_as_high_severity(self):
        events = [make_event(EventType.USER_CREATED, ip="203.0.113.5", user="joao")]
        findings = AccountCreationDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].severity.value == "Alta"

    def test_internal_normal_creation_is_medium_severity(self):
        events = [make_event(EventType.USER_CREATED, ip="192.168.1.10", user="joao")]
        findings = AccountCreationDetector().analyze(events)
        assert len(findings) == 1
        assert findings[0].severity.value == "Média"


class TestSSHParser:
    def test_parses_failed_password_line(self):
        line = "Jul 20 14:32:01 srv sshd[1234]: Failed password for root from 203.0.113.5 port 51422 ssh2"
        parser = SSHParser()
        event = parser._parse_line(line, "auth.log")
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.source_ip == "203.0.113.5"
        assert event.username == "root"

    def test_parses_accepted_password_line(self):
        line = "Jul 20 14:32:05 srv sshd[1234]: Accepted password for gustavo from 192.168.1.10 port 51423 ssh2"
        parser = SSHParser()
        event = parser._parse_line(line, "auth.log")
        assert event.event_type == EventType.AUTH_SUCCESS
        assert event.username == "gustavo"

    def test_can_parse_detects_ssh_format(self):
        sample = ["Jul 20 14:32:01 srv sshd[1234]: Failed password for root from 203.0.113.5 port 51422 ssh2"]
        assert SSHParser().can_parse("auth.log", sample) is True

    def test_can_parse_rejects_non_ssh_format(self):
        sample = ["203.0.113.5 - - [20/Jul/2026:14:32:01 +0000] \"GET / HTTP/1.1\" 200 512"]
        assert SSHParser().can_parse("access.log", sample) is False
