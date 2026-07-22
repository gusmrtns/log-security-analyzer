#!/usr/bin/env python3
"""
sample-logs/generate_sample_logs.py

Gera logs sintéticos realistas para testar o analyzer sem depender de uma VM real.
Inclui cenários "limpos" (tráfego normal) e cenários "sujos" (ataques simulados),
propositalmente, para validar tanto falsos positivos quanto detecções corretas.

Uso:
    python sample-logs/generate_sample_logs.py
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # Reprodutibilidade: mesmos logs a cada execução.

NOW = datetime(2026, 7, 20, 9, 0, 0)

NORMAL_USERS = ["gustavo", "carla", "root", "deploy"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
ATTACKER_IP = "203.0.113.5"
ENUM_ATTACKER_IP = "198.51.100.9"


def fmt_syslog(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")


def generate_auth_log(path: str):
    lines = []
    t = NOW

    # 1. Tráfego normal: logins bem-sucedidos espalhados, incluindo alguns fora de horário.
    for i in range(15):
        t += timedelta(minutes=random.randint(5, 40))
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        lines.append(f"{fmt_syslog(t)} srv sshd[{1000+i}]: Accepted password for {user} from {ip} port {40000+i} ssh2")

    # 2. Cenário de força bruta: 8 falhas do mesmo IP em ~3 minutos, mesmo usuário (root).
    brute_start = NOW + timedelta(hours=2)
    for i in range(8):
        ts = brute_start + timedelta(seconds=i * 20)
        lines.append(f"{fmt_syslog(ts)} srv sshd[{2000+i}]: Failed password for root from {ATTACKER_IP} port {50000+i} ssh2")

    # 3. Cenário de enumeração de usuários: mesmo IP testando vários usernames diferentes.
    enum_start = NOW + timedelta(hours=4)
    for i, user in enumerate(["admin", "test", "oracle", "postgres", "backup", "guest"]):
        ts = enum_start + timedelta(seconds=i * 15)
        lines.append(f"{fmt_syslog(ts)} srv sshd[{3000+i}]: Invalid user {user} from {ENUM_ATTACKER_IP} port {51000+i}")

    # 4. Login fora de horário comercial (23h) — usuário legítimo, mas fora da janela.
    off_hours = NOW.replace(hour=23, minute=15)
    lines.append(f"{fmt_syslog(off_hours)} srv sshd[4000]: Accepted password for carla from 192.168.1.11 port 52000 ssh2")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] {path} gerado ({len(lines)} linhas)")


def generate_apache_log(path: str):
    lines = []
    t = NOW

    paths = ["/", "/login", "/products", "/about", "/contact"]
    for i in range(30):
        t += timedelta(minutes=random.randint(1, 10))
        ip = random.choice(NORMAL_IPS + [ATTACKER_IP])
        status = 200
        path_hit = random.choice(paths)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts_str}] "GET {path_hit} HTTP/1.1" {status} 512')

    # Varredura de endpoints sensíveis a partir do IP atacante (gera volume + 404s).
    scan_start = NOW + timedelta(hours=1)
    for i, p in enumerate(["/admin", "/wp-login.php", "/.env", "/config.php", "/phpmyadmin", "/.git/config"]):
        ts = scan_start + timedelta(seconds=i * 5)
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ATTACKER_IP} - - [{ts_str}] "GET {p} HTTP/1.1" 404 210')

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] {path} gerado ({len(lines)} linhas)")


def generate_windows_csv(path: str):
    import csv

    rows = [["TimeCreated", "Id", "LevelDisplayName", "Message"]]
    t = NOW

    for i in range(10):
        t += timedelta(minutes=random.randint(5, 30))
        ts_str = t.strftime("%m/%d/%Y %H:%M:%S")
        rows.append([ts_str, "4624", "Information",
                     f"An account was successfully logged on. Account Name: {random.choice(NORMAL_USERS)} Source Network Address: {random.choice(NORMAL_IPS)}"])

    # Criação suspeita de conta administrativa.
    t += timedelta(minutes=10)
    ts_str = t.strftime("%m/%d/%Y %H:%M:%S")
    rows.append([ts_str, "4720", "Information",
                 f"A user account was created. Account Name: backdoor_adm Source Network Address: {ATTACKER_IP}"])

    with open(path, "w", newline="") as f:
        csv.writer(f).writerows(rows)

    print(f"[+] {path} gerado ({len(rows) - 1} linhas)")


if __name__ == "__main__":
    generate_auth_log("sample-logs/auth.log")
    generate_apache_log("sample-logs/access.log")
    generate_windows_csv("sample-logs/windows_events.csv")
    print("\nLogs sintéticos prontos. Teste com:")
    print("  python analyzer.py sample-logs/auth.log")
