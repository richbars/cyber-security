import logging
import os
from datetime import datetime, timedelta

import psutil
import requests
import win32api
import win32security

# CONFIGS
suspicious_ports = [1337, 4444, 6666, 9001, 5050, 31337, 2222, 12345]
trusted_dirs = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)']
suspicious_keywords = ['svchostsx', 'chrome2', 'winupdate', 'taskhostx', 'expl0rer']
max_exe_age_minutes = 30
trusted_country = "BR"  # Altere para seu país (ex: "BR" para Brasil)

# LOG
now = datetime.now()
log_filename = f"log_netmon_{now.strftime('%Y-%m-%d_%H-%M-%S')}_{now.strftime('%f')}.log"
logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    encoding='utf-8'
)

"""
PTBR:

NetMon - Monitor de conexões de rede para Blue Teams

Este script analisa conexões de rede ESTABLISHED no sistema e identifica possíveis processos suspeitos.
Ele verifica nomes e caminhos de processos, privilégios administrativos, assinatura digital, data de criação do executável,
IP remoto internacional e uso de portas potencialmente maliciosas.

Ideal para uso em kits de defesa (Blue Team) ou monitoramento local de máquinas comprometidas.

US:

NetMon - Network connection monitor for Blue Teams

This script scans all ESTABLISHED network connections and flags potentially suspicious processes.
It checks process names and paths, admin privileges, digital signature, executable creation date,
foreign remote IPs, and use of potentially malicious ports.

Ideal for Blue Team defense kits or local threat monitoring on compromised machines.

"""


def is_path_suspicious(path):
    return not any(path.lower().startswith(td.lower()) for td in trusted_dirs)


def is_name_suspicious(name):
    return any(kw in name.lower() for kw in suspicious_keywords)


def is_admin_process(proc):
    try:
        sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(proc.handle, win32security.TOKEN_QUERY),
            win32security.TokenUser
        )[0]
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return "admin" in name.lower() or "system" in name.lower()
    except:
        return False


def is_signed(exe_path):
    try:
        info = win32api.GetFileVersionInfo(exe_path, '\\')
        return bool(info)
    except:
        return False


def is_recent_exe(path):
    try:
        creation_time = datetime.fromtimestamp(os.path.getctime(path))
        return datetime.now() - creation_time <= timedelta(minutes=max_exe_age_minutes)
    except:
        return False


def is_foreign_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = response.json()
        return data.get("country") != trusted_country
    except:
        return False


def analyze_connections():
    print("🔍 Analisando conexões ESTABLISHED...\n")
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'ESTABLISHED' and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
                exe = proc.exe()
                local_port = conn.laddr.port
                remote_ip = conn.raddr.ip if conn.raddr else 'Desconhecido'

                alert = False
                alerts = []

                if local_port in suspicious_ports:
                    alert = True
                    alerts.append(f"⚠️ Porta suspeita usada: {local_port}")

                if is_path_suspicious(exe):
                    alert = True
                    alerts.append(f"⚠️ Caminho suspeito: {exe}")

                if is_name_suspicious(name):
                    alert = True
                    alerts.append(f"⚠️ Nome suspeito: {name}")

                if is_admin_process(proc):
                    alert = True
                    alerts.append("⚠️ Processo com privilégios administrativos")

                if not is_signed(exe):
                    alert = True
                    alerts.append("⚠️ Executável não possui assinatura digital")

                if is_recent_exe(exe):
                    alert = True
                    alerts.append("⚠️ Executável criado recentemente")

                if remote_ip != 'Desconhecido' and is_foreign_ip(remote_ip):
                    alert = True
                    alerts.append(f"⚠️ IP remoto internacional: {remote_ip}")

                if alert:
                    print(f"[!] Processo suspeito detectado:")
                    print(f"    PID: {conn.pid} | Nome: {name}")
                    print(f"    Executável: {exe}")
                    print(f"    IP Remoto: {remote_ip} | Porta Local: {local_port}")
                    for a in alerts:
                        print(f"    {a}")
                    print("-" * 60)

                    logging.info(
                        f"PID: {conn.pid} | Processo: {name} | EXE: {exe} | IP: {remote_ip} | Porta: {local_port} | ALERTAS: {alerts}")

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue


if __name__ == '__main__':
    analyze_connections()
    print(f"\n📄 Log salvo em: {log_filename}")
